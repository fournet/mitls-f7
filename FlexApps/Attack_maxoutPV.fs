#light "off"

module FlexApps.Attack_maxoutPV

open Bytes
open Error
open TLSInfo
open TLSConstants

open FlexTLS
open FlexTypes
open FlexConstants
open FlexConnection
open FlexClientHello
open FlexClientKeyShare
open FlexClientKeyExchange
open FlexServerHello
open FlexServerKeyShare
open FlexServerKeyExchange
open FlexCertificate
open FlexServerHelloDone
open FlexCertificateVerify
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets




type Attack_maxoutPV =
    class

    static member client (server_name:string, ?port:int, ?st:state, ?timeout:int) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let timeout = defaultArg timeout 0 in

        // We need to use the negotiable groups extension for TLS 1.3
        let cfg = {defaultConfig with maxVer = TLS_1p3; negotiableDHGroups = [DHE2432]} in
        
        // Start TCP connection with the server if no state is provided by the user
        let st,_ = 
            match st with
            | None -> FlexConnection.clientOpenTcpConnection(server_name,server_name,port,cfg.maxVer,timeout=timeout)
            | Some(st) -> st,TLSInfo.defaultConfig
        in

        // We want to ensure a ciphersuite
        let fch = {FlexConstants.nullFClientHello with
            pv = Some(cfg.maxVer);
            ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_GCM_SHA256]) } in

        let st,nsc,fch   = FlexClientHello.send(st,fch,cfg) in
        let st,nsc,fcks  = FlexClientKeyShare.send(st,nsc) in

        let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
        let st,nsc,fske  = FlexServerKeyExchange.receiveDHE(st,nsc) in
        let st,fshd      = FlexServerHelloDone.receive(st) in

//        let res = Tcp.read st.ns 15 in
//        st
        let st,nsc,fcke  = FlexClientKeyExchange.sendDHE(st,nsc) in
        let st,_         = FlexCCS.send(st) in
            
        // Start encrypting
        let st           = FlexState.installWriteKeys st nsc in
            
        let st,ffC       = FlexFinished.send(st,nsc,Client) in
        let st,_,_       = FlexCCS.receive(st) in

        // Start decrypting
        let st           = FlexState.installReadKeys st nsc in

        let st,ffS       = FlexFinished.receive(st,nsc,Server) in
        st
    end