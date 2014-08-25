#light "off"

module FlexClientHello

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
let fillFClientHelloANDConfig (fch:FClientHello) (cfg:config) : FClientHello * config =
    
    (* pv = Is there some pv ? If no, check config maxVer *)
    (* !!! BB !!! : There is a corner case when the user sets fch pv to default because it should have priority over cfg.maxVer *)
    let pv =
        match fch.pv = nullFClientHello.pv with
        | false -> fch.pv
        | true -> cfg.maxVer
    in

    (* rand = Is there random bytes ? If no, create some *)
    let rand =
        match fch.rand = nullFClientHello.rand with
        | false -> fch.rand
        | true -> Nonce.mkHelloRandom()
    in

    (* sid = Is there a sid ? If no, get the default empty one *)
    let sid = fch.sid in
    
    (* suites = Is there some ? If no, check config *)
    (* !!! BB !!! : There is a corner case when the user sets fch suites to default because it should have priority over cfg.ciphersuites *)
    let suites =
        match fch.suites = nullFClientHello.suites with
        | false -> fch.suites
        | true -> cfg.ciphersuites
    in

    (* comps = Is there some ? If no, check config *)
    (* !!! BB !!! : There is a corner case when the user sets fch comps to default because it should have priority over cfg.compressions *)
    let comps =
        match fch.comps = nullFClientHello.comps with
        | false -> fch.comps
        | true -> cfg.compressions
    in

    (* Update cfg with correct informations *)
    let cfg = { cfg with 
                maxVer = pv;
                ciphersuites = suites;
                compressions = comps;
              }
    in

    (* ext = Is there some ? If no, generate using config *)
    let ext =
        match fch.ext = nullFClientHello.ext with
        | false -> fch.ext
        | true -> 
            let ci = initConnection Client rand in
            let extL = prepareClientExtensions cfg ci empty_bytes None in
            clientExtensionsBytes extL
    in

    (* Update fch with correct informations and sets payload to empty bytes *)
    let fch = { nullFClientHello with
                pv = pv;
                rand = rand;
                sid = sid;
                suites = suites;
                comps = comps;
                ext = ext;
                payload = empty_bytes;
              } 
    in
    (fch,cfg)

(* Update channel's Epoch Init Protocol version to the one chosen by the user if we are in an InitEpoch, else do nothing *)
let fillStateEpochInitPvIFIsEpochInit (st:state) (fch:FClientHello) : state =
    if TLSInfo.isInitEpoch st.read.epoch then
        let st = FlexState.updateIncomingRecordEpochInitPV st fch.pv in
        let st = FlexState.updateOutgoingRecordEpochInitPV st fch.pv in
        st
    else
        st




type FlexClientHello =
    class

    (* Receive a ClientHello message from the network stream *)
    static member receive (st:state) : state * nextSecurityContext * FClientHello =
        
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_client_hello  ->    
            (match parseClientHello payload with
            | Error (ad,x) -> failwith x
            | Correct (pv,cr,sid,clientCipherSuites,cm,extensions) -> 
                let si  = { nullFSessionInfo with 
                            init_crand = cr 
                            } 
                in
                let nsc = { nullNextSecurityContext with si = si } in
                let fch = { nullFClientHello with
                            pv = pv;
                            rand = cr;
                            sid = sid;
                            suites = clientCipherSuites;
                            comps = cm;
                            ext = extensions;
                            payload = to_log;
                            } 
                in
                let st = fillStateEpochInitPvIFIsEpochInit st fch in
                (st,nsc,fch)
            )
        | _ -> failwith "recvClientHello : Message type should be HT_client_hello"
 

    (* Send a ClientHello message to the network stream *)
    static member send (st:state, ?fch:FClientHello, ?cfg:config, ?fp:fragmentationPolicy) : state * nextSecurityContext * FClientHello =

        let ns = st.ns in
        let fp = defaultArg fp defaultFragmentationPolicy in
        let fch = defaultArg fch nullFClientHello in
        let cfg = defaultArg cfg defaultConfig in
        
        let fch,cfg = fillFClientHelloANDConfig fch cfg in
        let st = fillStateEpochInitPvIFIsEpochInit st fch in

        let msgb = HandshakeMessages.clientHelloBytes cfg fch.rand fch.sid fch.ext in
        let st = FlexHandshake.send(st,HT_client_hello,msgb,fp) in
        (* TODO : How should we deal with nextSecurityContext depending in IsInitEpoch ? *)
        let si  = { nullFSessionInfo with init_crand = fch.rand } in
        let nsc = { nullNextSecurityContext with si = si } in
        (* !!! BB !!! should be payload = payload but here we don't have it back, we only have access to the message bytes *)
        let fch = { fch with payload = msgb } in
        st,nsc,fch
    
    end
