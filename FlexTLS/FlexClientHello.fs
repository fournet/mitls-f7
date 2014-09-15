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
    // FIXME : There is a corner case when the user sets fch pv to default because it should have priority over cfg.maxVer
    let pv =
        match fch.pv = FlexConstants.nullFClientHello.pv with
        | false -> fch.pv
        | true -> cfg.maxVer
    in

    (* rand = Is there random bytes ? If no, create some *)
    let rand =
        match fch.rand = FlexConstants.nullFClientHello.rand with
        | false -> fch.rand
        | true -> Nonce.mkHelloRandom()
    in

    (* sid = Is there a sid ? If no, get the default empty one *)
    let sid = fch.sid in
    
    (* suites = Is there some ? If no, check config *)
    // FIXME : There is a corner case when the user sets fch suites to default because it should have priority over cfg.ciphersuites
    let suites =
        match fch.suites = FlexConstants.nullFClientHello.suites with
        | false -> fch.suites
        | true -> (match FlexConstants.names_of_cipherSuites cfg.ciphersuites with
            | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(csl) -> csl)
    in

    (* comps = Is there some ? If no, check config *)
    // FIXME : There is a corner case when the user sets fch comps to default because it should have priority over cfg.compressions
    let comps =
        match fch.comps = FlexConstants.nullFClientHello.comps with
        | false -> fch.comps
        | true -> cfg.compressions
    in

    (* Update cfg with correct informations *)
    let cfg = { cfg with 
                maxVer = pv;
                ciphersuites = TLSConstants.cipherSuites_of_nameList suites;
                compressions = comps;
              }
    in

    (* ext = Is there some ? If no, generate using config *)
    let ext =
        match fch.ext = FlexConstants.nullFClientHello.ext with
        | false -> fch.ext
        | true -> 
            let ci = initConnection Client rand in
            let extL = prepareClientExtensions cfg ci empty_bytes None in
            clientExtensionsBytes extL
    in

    (* Update fch with correct informations and sets payload to empty bytes *)
    let fch = { pv = pv;
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
            | Error (ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (pv,cr,sid,clientCipherSuites,cm,extensions) -> 
                let si  = { FlexConstants.nullSessionInfo with 
                            init_crand = cr 
                            } 
                in
                let nsc = { FlexConstants.nullNextSecurityContext with
                                si = si;
                                crand = cr } in
                let suites = match FlexConstants.names_of_cipherSuites clientCipherSuites with
                    | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
                    | Correct(suites) -> suites
                in
                let fch = { FlexConstants.nullFClientHello with
                            pv = pv;
                            rand = cr;
                            sid = sid;
                            suites = suites;
                            comps = cm;
                            ext = extensions;
                            payload = to_log;
                            } 
                in
                let st = fillStateEpochInitPvIFIsEpochInit st fch in
                (st,nsc,fch)
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "Message type should be HT_client_hello")
 
     (* Send a ClientHello message to the network stream *)
    static member prepare (st:state, ?fch:FClientHello, ?cfg:config) : bytes * state * nextSecurityContext * FClientHello =
        let fch = defaultArg fch FlexConstants.nullFClientHello in
        let cfg = defaultArg cfg defaultConfig in
        let fch,cfg = fillFClientHelloANDConfig fch cfg in
        let st = fillStateEpochInitPvIFIsEpochInit st fch in
        let payload = HandshakeMessages.clientHelloBytes cfg fch.rand fch.sid fch.ext in
        let si  = { FlexConstants.nullSessionInfo with init_crand = fch.rand } in
        let nsc = { FlexConstants.nullNextSecurityContext with
                        si = si;
                        crand = fch.rand } in
        let fch = { fch with payload = payload } in
        payload,st,nsc,fch

    (* Send a ClientHello message to the network stream *)
    static member send (st:state, ?fch:FClientHello, ?cfg:config, ?fp:fragmentationPolicy) : state * nextSecurityContext * FClientHello =
        let ns = st.ns in
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let fch = defaultArg fch FlexConstants.nullFClientHello in
        let cfg = defaultArg cfg defaultConfig in
        
        let fch,cfg = fillFClientHelloANDConfig fch cfg in
        let st = fillStateEpochInitPvIFIsEpochInit st fch in

        let payload = HandshakeMessages.clientHelloBytes cfg fch.rand fch.sid fch.ext in
        let st = FlexHandshake.send(st,payload,fp) in
        // TODO : How should we deal with nextSecurityContext depending on IsInitEpoch ?
        let si  = { FlexConstants.nullSessionInfo with init_crand = fch.rand } in
        let nsc = { FlexConstants.nullNextSecurityContext with
                        si = si;
                        crand = fch.rand } in
        let fch = { fch with payload = payload } in
        st,nsc,fch
    
    end
