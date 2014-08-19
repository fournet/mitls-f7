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
 