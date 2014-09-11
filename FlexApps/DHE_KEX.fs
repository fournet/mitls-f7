#light "off"

module DHE_KEX

open Tcp
open Bytes
open Error
open TLS
open TLSInfo
open TLSConstants

open FlexTypes
open FlexConstants
open FlexConnection
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexServerKeyExchange
open FlexCertificateRequest
open FlexCertificateVerify
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets




type DHE_KEX =
    class

    (* Run a full Handshake DHE with server side authentication only *)
    static member client (server_name:string, ?port:int) : unit =
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // Start TCP connection with the server
        let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port) in

        // Typical DHE key exchange messages

        // Ensure we use DHE
        let fch = {FlexConstants.nullFClientHello with
            suites = [TLS_DHE_RSA_WITH_AES_128_CBC_SHA] } in
        let st,nsc,fch   = FlexClientHello.send(st,fch) in
        let st,nsc,fsh   = FlexServerHello.receive(st,nsc) in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
        let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
        let st,fshd      = FlexServerHelloDone.receive(st) in
        let st,nsc,fcke  = FlexClientKeyExchange.sendDHE(st,nsc) in
        let st,_         = FlexCCS.send(st) in
            
        // Start encrypting
        let st           = FlexState.installWriteKeys st nsc in
        let log          = fch.payload @| fsh.payload @| fcert.payload @| fske.payload @| fshd.payload @| fcke.payload in
            
        let st,ffC       = FlexFinished.send(st, logRoleNSC=(log,Client,nsc)) in
        let st,_         = FlexCCS.receive(st) in

        // Start decrypting
        let st           = FlexState.installReadKeys st nsc in

        let log          = log @| ffC.payload in
        let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.ms Server log in
        let st,ffS        = FlexFinished.receive(st) in
            
        // Check match of reveived log with the correct one
        if not (verify_data = ffS.verify_data)
        then
            failwith (perror __SOURCE_FILE__ __LINE__ "Server verify_data doesn't match")
        else
        ()
    

    static member server (listening_address:string, ?cn:string, ?port:int) : unit =
        let cn = defaultArg cn listening_address in
        let port = defaultArg port FlexConstants.defaultTCPPort in
        match Cert.for_signing FlexConstants.sigAlgs_ALL cn FlexConstants.sigAlgs_RSA with
        | None -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Private key not found for the given CN: %s" cn))
        | Some(chain,_,_) -> DHE_KEX.server(listening_address,chain,port)

    static member server (listening_address:string, chain:Cert.chain, ?port:int) : unit =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let cn =
            match Cert.get_hint chain with
            | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Could not parse given certficate")
            | Some(cn) -> cn
        in

        // Accept TCP connection from the client
        let st,cfg = FlexConnection.serverOpenTcpConnection(listening_address,cn,port) in

        // Start typical DHE key exchange
        let st,nsc,fch   = FlexClientHello.receive(st) in

        // Sanity check: our preferred ciphersuite is there
        if not (List.exists (fun cs -> cs = TLS_DHE_RSA_WITH_AES_128_CBC_SHA) fch.suites) then
            failwith (perror __SOURCE_FILE__ __LINE__ "No suitable ciphersuite given")
        else

        // Ensure we send our preferred ciphersuite
        let fsh = {FlexConstants.nullFServerHello with suite = TLS_DHE_RSA_WITH_AES_128_CBC_SHA} in
        let st,nsc,fsh   = FlexServerHello.send(st,nsc,fsh) in
        let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in
        let st,nsc,fske  = FlexServerKeyExchange.sendDHE(st,nsc) in
        let st,fshd      = FlexServerHelloDone.send(st) in
        let st,nsc,fcke  = FlexClientKeyExchange.receiveDHE(st,nsc) in
        let st,_         = FlexCCS.receive(st) in

        let log = fch.payload @| fsh.payload @| fcert.payload @| fske.payload @| fshd.payload @| fcke.payload in
        let verify_data = FlexSecrets.makeVerifyData nsc.si nsc.ms Client log in

        // Start decrypting
        let st          = FlexState.installReadKeys st nsc in
        let st,ffC       = FlexFinished.receive(st) in

        // Check verify_data
        if not (verify_data = ffC.verify_data) then
            failwith (perror __SOURCE_FILE__ __LINE__ "Client verify_data doesn't match")
        else

        let st,_   = FlexCCS.send(st) in
            
        // Start encrypting
        let st     = FlexState.installWriteKeys st nsc in
        let log    = log @| ffC.payload in
        let _      = FlexFinished.send(st,logRoleNSC=(log,Server,nsc)) in
        ()

    end
