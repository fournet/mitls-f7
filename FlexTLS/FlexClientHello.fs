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
open FlexFragment




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




type FlexClientHello =
    class

    (* Receive a ClientHello message from the network stream *)
    static member receive (st:state) : state * SessionInfo * FClientHello =
    
        let buf = st.read_s.buffer in
        let st,hstypeb,len,payload,to_log,rem = FlexFragment.getHSMessage st buf in
    
        match parseHt hstypeb with
        | Error (ad,x) -> failwith x
        | Correct(hst) ->
            match hst with
            | HT_client_hello  ->    
                (match parseClientHello payload with
                | Error (ad,x) -> failwith x
                | Correct (pv,cr,sid,clientCipherSuites,cm,extensions) -> 
                    let si  = { nullFSessionInfo with 
                                init_crand = cr 
                              } 
                    in
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
                    (st,si,fch)
                    )
            | _ -> failwith "recvClientHello : Message type should be HT_client_hello"
 

    (* Send a ClientHello message to the network stream *)
    static member send (st:state, ?ofch:FClientHello, ?ocfg:config) : state * SessionInfo * FClientHello =

        let ns = st.ns in

        let fch = defaultArg ofch nullFClientHello in
        let cfg = defaultArg ocfg defaultConfig in
        
        let fch,cfg = fillFClientHelloANDConfig fch cfg in

        let msgb = HandshakeMessages.clientHelloBytes cfg fch.rand fch.sid fch.ext in
        let len = length msgb in
        let rg : Range.range = (len,len) in

        let id = TLSInfo.id st.write_s.epoch in
        let frag = TLSFragment.fragment id Handshake rg msgb in
        let (nst, b) = Record.recordPacketOut st.write_s.epoch st.write_s.record fch.pv rg Handshake frag in
        let wst = {st.write_s with record = nst} in
        let st = {st with write_s = wst} in

        let si  = { nullFSessionInfo with init_crand = fch.rand } in
        let fch = { fch with payload = b } in

        match Tcp.write ns b with
        | Error(x) -> failwith x
        | Correct() -> (st,si,fch)
    
    end
