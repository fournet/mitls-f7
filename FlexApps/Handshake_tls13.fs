#light "off"

module FlexApps.Handshake_tls13

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
open FlexServerHello
open FlexServerKeyShare
open FlexCertificate
open FlexServerHelloDone
open FlexCertificateVerify
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets




type Handshake_tls13 =
    class

    static member client (address:string, ?cn:string, ?port:int) : state =
        let cn = defaultArg cn address in
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // We need to use the negotiable groups extension for TLS 1.3
        let cfg = {defaultConfig with maxVer = TLS_1p3; negotiableDHGroups = [DHE2432; DHE3072; DHE4096; DHE6144; DHE8192]} in

        // Start TCP connection with the server
        let st,_ = FlexConnection.clientOpenTcpConnection(address,cn,port,cfg.maxVer) in

        // We want to ensure a ciphersuite
        let fch = {FlexConstants.nullFClientHello with
            pv = Some(cfg.maxVer);
            ciphersuites = Some([TLS_DHE_RSA_WITH_AES_128_GCM_SHA256]) } in

        let st,nsc,fch   = FlexClientHello.send(st,fch,cfg) in
        let st,nsc,fcks  = FlexClientKeyShare.send(st,nsc) in

        let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
        let st,nsc,fsks  = FlexServerKeyShare.receive(st,nsc) in

        // Peer advertize that it will encrypt the traffic
        let st,_,_       = FlexCCS.receive(st) in
        let st           = FlexState.installReadKeys st nsc in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in

        let log = fch.payload @| fcks.payload @| fsh.payload @| fsks.payload @| fcert.payload in
        let st,scertv    = FlexCertificateVerify.receive(st,nsc,FlexConstants.sigAlgs_ALL,log=log) in
        
        let log = log @| scertv.payload in
        let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Server log in
        let st,ffS       = FlexFinished.receive(st,verify_data) in
        
        // We advertize that we will encrypt the traffic
        let st,_         = FlexCCS.send(st) in
        let st           = FlexState.installWriteKeys st nsc in
        
        let log          = log @| ffS.payload in    
        let st,ffC       = FlexFinished.send(st,logRoleNSC=(log,Client,nsc)) in
        st

    static member server (address:string, ?cn:string, ?port:int) : state =
        let cn = defaultArg cn address in
        let port = defaultArg port FlexConstants.defaultTCPPort in
        
        // We need to use the negotiable groups extension for TLS 1.3
        let cfg = {defaultConfig with maxVer = TLS_1p3; negotiableDHGroups = [DHE2432; DHE3072; DHE4096; DHE6144; DHE8192]} in

        // Resolve cn to a cert and key pair
        // TODO: May go in a different overload
        match Cert.for_signing FlexConstants.sigAlgs_ALL cn FlexConstants.sigAlgs_RSA with
        | None -> failwith "Failed to retreive certificate data"
        | Some(chain,sigAlg,skey) ->

        // Start TCP connection listening to a client
        let st,_ = FlexConnection.serverOpenTcpConnection(address,cn,port,cfg.maxVer) in

        let st,nsc,fch   = FlexClientHello.receive(st) in
        if not ( List.exists (fun x -> x = TLS_DHE_RSA_WITH_AES_128_GCM_SHA256) (FlexClientHello.getCiphersuites fch)) then
            failwith (perror __SOURCE_FILE__ __LINE__ "Unsuitable ciphersuite")
        else

        let st,nsc,fcke  = FlexClientKeyShare.receive(st,nsc) in

        let st,nsc,fsh   = FlexServerHello.send(st,fch,nsc=nsc,cfg=cfg) in
        let st,nsc,fske  = FlexServerKeyShare.send(st,nsc) in

        // We advertize that we will encrypt the traffic
        let st,_         = FlexCCS.send(st) in
        let st           = FlexState.installWriteKeys st nsc in
        let st,nsc,fcert = FlexCertificate.send(st,Server,chain,nsc) in

        let log = fch.payload @| fcke.payload @| fsh.payload @| fske.payload @| fcert.payload in
        let st,scertv    = FlexCertificateVerify.send(st,log,nsc.si,sigAlg,skey) in

        let log = log @| scertv.payload in        
        let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Server log in
        let st,ffS       = FlexFinished.send(st,verify_data) in
        
        // Peer advertize that it will encrypt the traffic
        let st,_,_       = FlexCCS.receive(st) in
        let st           = FlexState.installReadKeys st nsc in
        
        let log          = log @| ffS.payload in    
        let st,ffC       = FlexFinished.send(st,logRoleNSC=(log,Client,nsc)) in
        st

    end
