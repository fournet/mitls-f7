#light "off"

module FlexApps.Handshake_resumption

open Bytes
open Error
open TLSInfo
open TLSConstants

open FlexTLS
open FlexTypes
open FlexConstants
open FlexConnection
open FlexSecrets
open FlexClientHello
open FlexServerHello
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets




type Handshake_resumption =
    class

    (* Run a Handshake resumption with server side authentication only *)
    static member client (st:state, server_name:string, ?port:int) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let e = st.read.epoch in
        let k = st.read.keys in
        Handshake_resumption.client(server_name,e,k,port)

    static member client (server_name:string, e:epoch, k:keys, ?port:int) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let ms = k.ms in
        let si = TLSInfo.epochSI e in
        Handshake_resumption.client(server_name,si,ms,port)

    static member client (server_name:string, si:SessionInfo, ms:bytes, ?port:int) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // Start TCP connection with the server
        let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port) in

        let ciphersuite = 
            match name_of_cipherSuite si.cipher_suite with
            | Error(ad,x) -> failwith x
            | Correct(csn) -> csn
        in
        let fch          = {FlexConstants.nullFClientHello with sid = Some(si.sessionID); ciphersuites = Some([ciphersuite]) } in

        let st,nsc,fch   = FlexClientHello.send(st,fch) in
        let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in

        // Check whether the server authorized or refused the resumption and if the data is matching previous session
        if not (si.sessionID = getSID fsh) then failwith "Server refused resumption" else
        if not (ciphersuite = getCiphersuite fsh) then failwith "Server resumption data doesn't match previous session" else
        if not (si.protocol_version = getPV fsh) then failwith "Server resumption data doesn't match previous session" else

        // Install the new keys according to the previous master secret
        let keys         = { nsc.keys with ms = ms } in
        let nsc          = { nsc with keys = keys; si = si } in
        let nsc          = FlexSecrets.fillSecrets(st,Client,nsc) in

        let st,_,_       = FlexCCS.receive(st) in

        // Start decrypting
        let st           = FlexState.installReadKeys st nsc in

        let log          = fch.payload @| fsh.payload in
        let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Server log in
        let st,ffS       = FlexFinished.receive(st,verify_data) in

         let st,_         = FlexCCS.send(st) in
            
        // Start encrypting
        let st           = FlexState.installWriteKeys st nsc in

        let log          = log @| ffS.payload in
        let st,ffC       = FlexFinished.send(st,logRoleNSC=(log,Client,nsc)) in
        st

//
// WORK IN PROGRESS
//
    static member server (server_name:string, ?sDB:SessionDB.t, ?port:int) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let sDB  = defaultArg sDB (SessionDB.create defaultConfig) in

        // Start TCP connection with the server
        let st,_ = FlexConnection.serverOpenTcpConnection(server_name,server_name,port) in

        // Start the handshake
        let st,nsc,fch   = FlexClientHello.receive(st) in

        // Retreive session information and master secret if resumption is possible
        let si,ms =
            match SessionDB.select sDB (FlexClientHello.getSID fch) Client server_name with
            | None -> failwith "Unable to resume a requested session"
            | Some(si,ams) -> si,(PRF.leak (msi si) ams)
        in
        //BB FIXME : Here the list of the server extensions is not correct
        // Server Hello should be reconstructed from the retreived session info
        let st,fsh   = FlexServerHello.send(st,si,[]) in

        // Install the new keys according to the previous master secret
        let keys         = { nsc.keys with ms = ms } in
        let nsc          = { nsc with keys = keys; si = si } in
        let nsc          = FlexSecrets.fillSecrets(st,Server,nsc) in

        let st,_         = FlexCCS.send(st) in

        // Start encrypting
        let st           = FlexState.installWriteKeys st nsc in

        let log          = fch.payload @| fsh.payload in
        let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Server log in
        let st,ffS       = FlexFinished.send(st,verify_data) in

         let st,_,_      = FlexCCS.receive(st) in
            
        // Start decrypting
        let st           = FlexState.installReadKeys st nsc in

        let log          = log @| ffS.payload in
        let st,ffC       = FlexFinished.receive(st,logRoleNSC=(log,Client,nsc)) in
        st

    end
