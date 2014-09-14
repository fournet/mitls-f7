#light "off"

module Attack_FragmentClientHello

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
open FlexCertificateRequest
open FlexCertificateVerify
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets




type Attack_FragmentClientHello =
    class

    (* Run a full Handshake RSA with server side authentication only *)
    static member run (server_name:string, ?port:int, ?fp:fragmentationPolicy) : unit =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let fp = defaultArg fp (All(5)) in

        // Start TCP connection with the server
        let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port) in

        // Typical RSA key exchange messages

        // Ensure we use RSA
        let fch = {FlexConstants.nullFClientHello with
            suites = [TLS_RSA_WITH_AES_128_CBC_SHA] } in

        let st,nsc,fch   = FlexClientHello.send(st,fch,fp=fp) in
        let st,nsc,fsh   = FlexServerHello.receive(st,nsc) in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
        let st,fshd      = FlexServerHelloDone.receive(st) in
        let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
        let st,_         = FlexCCS.send(st) in
            
        // Start encrypting
        let st           = FlexState.installWriteKeys st nsc in
        
        let log          = fch.payload @| fsh.payload @| fcert.payload @| fshd.payload @| fcke.payload in
        let st,ffC       = FlexFinished.send(st,logRoleNSC=(log,Client,nsc)) in
        let st,_         = FlexCCS.receive(st) in

        // Start decrypting
        let st           = FlexState.installReadKeys st nsc in

        let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.ms Server (log @| ffC.payload) in
        let st,ffS       = FlexFinished.receive(st,verify_data) in
        ()

    end
