#light "off"

module Handshake_resumption

open Bytes
open TLSInfo

open FlexTypes
open FlexConstants
open FlexConnection
open FlexClientHello
open FlexServerHello
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets




type Handshake_resumption =
    class

//    (* Run a Handshake resumption with server side authentication only *)
//    static member client (server_name:string, sid:bytes, crand:bytes, srand:bytes, ?port:int) : state =
//        let port = defaultArg port FlexConstants.defaultTCPPort in
//
//        // Start TCP connection with the server
//        let st,_ = FlexConnection.clientOpenTcpConnection(server_name,server_name,port) in
//
//        let st,nsc,fch   = FlexClientHello.send(st) in
//        let st,nsc,fsh   = FlexServerHello.receive(st,nsc) in
//
//        let st,_         = FlexCCS.send(st) in
//            
//        // Start encrypting
//        let st           = FlexState.installWriteKeys st nsc in
//        let log          = fch.payload @| fsh.payload in
//        let st,ffC       = FlexFinished.send(st,logRoleNSC=(log,Client,nsc)) in
// 
//        let st,_         = FlexCCS.receive(st) in
//
//        // Start decrypting
//        let st           = FlexState.installReadKeys st nsc in
//        let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Server (log @| ffC.payload) in
//        let st,ffS       = FlexFinished.receive(st,verify_data) in
//        st

    end
