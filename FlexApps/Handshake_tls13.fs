#light "off"

module Handshake_tls13

open Bytes
open Error
open TLSInfo
open TLSConstants

open FlexTypes
open FlexConstants
open FlexConnection
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexServerKeyExchange
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets




type Handshake_tls13 =
    class

    static member client (server_name:string, ?port:int) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // Start TCP connection with the server
        let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port,TLS_1p3) in

        // We want to ensure a ciphersuite
        let fch = {FlexConstants.nullFClientHello with
            suites = [TLS_DHE_RSA_WITH_AES_128_CBC_SHA] } in

        // We need to use the negociable groups extension for TLS 1.3
        let cfg = {defaultConfig with negotiableDHGroups = [DHE2432; DHE3072; DHE4096; DHE6144; DHE8192]} in

        let st,nsc,fch   = FlexClientHello.send(st,fch,cfg) in
        let st,fcke      = FlexClientKeyExchangeTLS13.send(st) in

        let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
        let st,nsc,fske  = FlexServerKeyExchangeTLS13.receive(st,nsc) in

        // Peer advertize that it will encrypt the traffic
        let st,_,_       = FlexCCS.receive(st) in
        let st           = FlexState.installReadKeys st nsc in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
        
        let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Server ( fch.payload @| fcke.payload @| fsh.payload @| fske.payload @| fcert.payload ) in
        let st,ffS       = FlexFinished.receive(st,verify_data) in
        
        // We advertize that we will encrypt the traffic
        let st,_         = FlexCCS.send(st) in
        let st           = FlexState.installWriteKeys st nsc in
        
        let log          = fch.payload @| fcke.payload @| fsh.payload @| fske.payload @| fcert.payload @| ffS.payload in    
        let st,ffC       = FlexFinished.send(st,logRoleNSC=(log,Client,nsc)) in
        st

    static member server (server_name:string, ?port:int) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // Start TCP connection listening to a client
        let st,_ = FlexConnection.serverOpenTcpConnection(server_name,server_name,port,TLS_1p3) in

        let st,nsc,fch   = FlexClientHello.receive(st) in
        let st,fcke      = FlexClientKeyExchangeTLS13.receive(st) in

        let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc) in
        let st,nsc,fske  = FlexServerKeyExchangeTLS13.send(st,nsc) in

        // We advertize that we will encrypt the traffic
        let st,_         = FlexCCS.send(st) in
        let st           = FlexState.installWriteKeys st nsc in
        let st,nsc,fcert = FlexCertificate.send(st,Server,nsc) in
        
        let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Client ( fch.payload @| fcke.payload @| fsh.payload @| fske.payload @| fcert.payload ) in
        let st,ffS       = FlexFinished.send(st,verify_data) in
        
        // Peer advertize that it will encrypt the traffic
        let st,_,_       = FlexCCS.receive(st) in
        let st           = FlexState.installReadKeys st nsc in
        
        let log          = fch.payload @| fcke.payload @| fsh.payload @| fske.payload @| fcert.payload @| ffS.payload in    
        let st,ffC       = FlexFinished.send(st,logRoleNSC=(log,Server,nsc)) in
        st

    end
