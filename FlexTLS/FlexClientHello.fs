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
    
    let ct,pv,len = parseHeader ns in
    
    let plaindata = 
        match Tcp.read ns len with
        | Error x         -> failwith "Tcp.read len bytes failed"
        | Correct payload ->
            Record.recordPacketIn st.read_s.epoch st.read_s.record ct payload
    in
    match plaindata with
    | Error x                   -> failwith "Unable to parse plain data"
    | Correct (rec_in,rg,frag)  ->
        let read_s = {st.read_s with record = rec_in} in
        let st = {st with read_s = read_s} in
        let id = TLSInfo.id st.read_s.epoch in
        let b = TLSFragment.reprFragment id ct rg frag in
        match HandshakeMessages.parseClientHello b with
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
                        payload = b;
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
 