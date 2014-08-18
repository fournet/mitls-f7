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

open FlexTypes
open FlexFragment

(*

let parseHt (b:bytes) = 
    match cbyte b with
    |   0uy  -> correct(HT_hello_request      )
    |   1uy  -> correct(HT_client_hello       )
    |   2uy  -> correct(HT_server_hello       )
    |  11uy  -> correct(HT_certificate        )
    |  12uy  -> correct(HT_server_key_exchange)
    |  13uy  -> correct(HT_certificate_request)
    |  14uy  -> correct(HT_server_hello_done  )
    |  15uy  -> correct(HT_certificate_verify )
    |  16uy  -> correct(HT_client_key_exchange)
    |  20uy  -> correct(HT_finished           )
    | _   -> let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_decode_error, reason)

let messageBytes ht data =
    let htb = htBytes ht in
    let vldata = vlbytes 3 data in
    htb @| vldata 

let parseMessage buf =
    (* Somewhat inefficient implementation:
       we repeatedly parse the first 4 bytes of the incoming buffer until we have a complete message;
       we then remove that message from the incoming buffer. *)
    if length buf < 4 then Correct(None) (* not enough data to start parsing *)
    else
        let (hstypeb,rem) = Bytes.split buf 1 in
        match parseHt hstypeb with
        | Error z ->  Error z
        | Correct(hstype) ->
            match vlsplit 3 rem with
            | Error z -> Correct(None) // not enough payload, try next time
            | Correct(res) ->
                let (payload,rem) = res in
                let to_log = messageBytes hstype payload in
                let res = (rem,hstype,payload,to_log) in
                let res = Some(res) in
                correct(res)

let parseMessageState (ci:ConnectionInfo) state = 
    match HandshakeMessages.parseMessage state with
    | Error(z) -> Error(z)
    | Correct(res) ->
        match res with
        | None -> correct(None)
        | Some(x) -> 
             let (rem,hstype,payload,to_log) = x in
             let st_in = { read_s with hs_s = rem }
             let state = { state with read_s = st_in } in
             let nx = (state,hstype,payload,to_log) in
             let res = Some(nx) in
             correct(res)
 *)

(* Receive a ClientHello message from the network stream *)
let recvClientHello (ns:NetworkStream) (st:state) : state * SessionInfo * FClientHello =
    
    let ct,pv,len = parseFragmentHeader ns in
    let st,buf = getFragmentContent ns ct len st in
    
    let st,hstypeb,len,payload,to_log,rem = getHSMessage ns st buf in
        
    match HandshakeMessages.parseClientHello payload with
    | Error (ad,x) -> failwith x
    | Correct (pv,cr,sid,clientCipherSuites,cm,extensions) -> 
        let si  = { nullFSessionInfo with 
                    init_crand = cr 
        } in
        let fch = { nullFClientHello with
                    pv = pv;
                    rand = cr;
                    sid = sid;
                    suites = clientCipherSuites;
                    comps = cm;
                    ext = extensions;
                    payload = payload;
        } in
        (st,si,fch)
                               

 

(* Send a ClientHello message to the network stream *)
let sendClientHello (ns:NetworkStream) (st:state) (cfg:config): state * SessionInfo * FClientHello =

    let sid = empty_bytes in
    let cr = Nonce.mkHelloRandom() in
    let ci = initConnection Client cr in
    let extL = prepareClientExtensions cfg ci empty_bytes None in
    let ext = clientExtensionsBytes extL in
    
    let b = HandshakeMessages.clientHelloBytes cfg cr sid ext in
    let len = length b in
    let rg : Range.range = (len,len) in

    let id = TLSInfo.id st.write_s.epoch in
    let frag_out = TLSFragment.fragment id Handshake rg b in
    let (nst, b) = Record.recordPacketOut st.write_s.epoch st.write_s.record cfg.maxVer rg Handshake frag_out in
    let wst = {st.write_s with record = nst} in
    let st = {st with write_s = wst} in

    let si  = { nullFSessionInfo with 
                init_crand = cr
    } in

    let fch = { nullFClientHello with 
                pv = cfg.maxVer;
                rand = cr;
                sid = sid;
                suites = cfg.ciphersuites;
                comps = cfg.compressions;
                ext = ext;
                payload = b;
    } in
    match Tcp.write ns b with
    | Error(x) -> failwith x
    | Correct() -> (st,si,fch)
 