#light "off"

module FlexServerHello

open Tcp
open Bytes
open Error
open System
open System.IO
open TLS
open TLSInfo
open TLSConstants
open TLSExtensions
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexState
open FlexHandshake




(* Inference on user provided information *)
let fillFServerHelloANDSi (fsh:FServerHello) (si:SessionInfo) : FServerHello * SessionInfo =
    (* rand = Is there random bytes ? If no, create some *)
    let rand =
        match fsh.rand = nullFServerHello.rand with
        | false -> fsh.rand
        | true -> Nonce.mkHelloRandom()
    in

    (* Update fch with correct informations and sets payload to empty bytes *)
    let fsh = { fsh with 
                rand = rand;
                payload = empty_bytes 
              } 
    in

    (* Update si with correct informations from fsh *)
    let si = { si with
               protocol_version = fsh.pv;
               sessionID = fsh.sid;
               cipher_suite = fsh.suite;
               compression = fsh.comp;
               init_srand = fsh.rand;
             } 
    in
    (fsh,si)

(* Update channel's Epoch Init Protocol version to the one chosen by the user if we are in an InitEpoch, else do nothing *)
let fillStateEpochInitPvIFIsEpochInit (st:state) (fsh:FServerHello) : state =
    if TLSInfo.isInitEpoch st.read.epoch then
        let st = FlexState.updateIncomingRecordEpochInitPV st fsh.pv in
        let st = FlexState.updateOutgoingRecordEpochInitPV st fsh.pv in
        st
    else
        st




type FlexServerHello = 
    class

    (* Receive a ServerHello message from the network stream *)
    static member receive (st:state, ?nsc:nextSecurityContext) : state * nextSecurityContext * FServerHello =
        let nsc = defaultArg nsc nullNextSecurityContext in
        let si = nsc.si in
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_server_hello  ->    
            (match parseServerHello payload with
            | Error (ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (pv,sr,sid,cs,cm,extensions) ->
                let si  = { si with 
                            init_srand = sr;
                            protocol_version = pv;
                            sessionID = sid;
                            cipher_suite = cs;
                            compression = cm;
                } in
                let nsc = { nsc with
                                si = si;
                                srand = sr } in
                let fsh = { pv = pv;
                            rand = sr;
                            sid = sid;
                            suite = cs;
                            comp = cm;
                            ext = extensions;
                            payload = to_log;
                } in
                let st = fillStateEpochInitPvIFIsEpochInit st fsh in
                (st,nsc,fsh)
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "message type should be HT_server_hello")
        
        
    (* Send a ServerHello message to the network stream *)
    static member send (st:state, ?nsc:nextSecurityContext, ?fsh:FServerHello, ?fp:fragmentationPolicy) : state * nextSecurityContext * FServerHello =
        let ns = st.ns in
        let fp = defaultArg fp defaultFragmentationPolicy in
        let fsh = defaultArg fsh nullFServerHello in
        let nsc = defaultArg nsc nullNextSecurityContext in
        let si = nsc.si in

        let fsh,si = fillFServerHelloANDSi fsh si in
        let nsc = { nsc with
                      si = si;
                      srand = fsh.rand } in
        let st = fillStateEpochInitPvIFIsEpochInit st fsh in

        let payload = HandshakeMessages.serverHelloBytes si fsh.rand fsh.ext in
        let st = FlexHandshake.send(st,payload,fp) in
        let fsh = { fsh with payload = payload } in
        st,nsc,fsh

    end
