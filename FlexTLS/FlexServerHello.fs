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
open FlexFragment




(* Receive a ServerHello message from the network stream *)
let recvServerHello (st:state) (si:SessionInfo) : state * SessionInfo * FServerHello =
    
    let buf = st.read_s.buffer in
    let st,hstypeb,len,payload,to_log,rem = getHSMessage st buf in
    
    match parseHt hstypeb with
    | Error (ad,x) -> failwith x
    | Correct(hst) ->
        match hst with
        | HT_server_hello  ->    
            (match parseServerHello payload with
            | Error (ad,x) -> failwith x
            | Correct (pv,sr,sid,cs,cm,extensions) -> 
                let si  = { si with 
                            init_srand = sr
                } in
                let fsh = { nullFServerHello with 
                            pv = pv;
                            rand = sr;
                            sid = sid;
                            suite = cs;
                            comp = cm;
                            ext = extensions;
                            payload = payload;
                } in
                (st,si,fsh)
                )
        | _ -> failwith "recvServerHello : message type should be HT_server_hello"
        
        
(* Send a ServerHello message to the network stream *)
let sendServerHello (st:state) (si:SessionInfo) (sh:FServerHello) : state * SessionInfo * FServerHello =
    
    let ns = st.ns in
    let pv = sh.pv in
    let cs = sh.suite in
    let comp = sh.comp in
    let ext = sh.ext in
    let sid = sh.sid in
    let sr = Nonce.mkHelloRandom() in
    let si =  { si with
                protocol_version = pv;
                sessionID = sid;
                init_srand = sr;
                cipher_suite = cs;
                compression = comp;
                extensions = []; // No extensions
    } in
    let b = HandshakeMessages.serverHelloBytes si sr ext in
    let len = length b in
    let rg : Range.range = (len,len) in

    let id = TLSInfo.id st.write_s.epoch in
    let frag_out = TLSFragment.fragment id Handshake rg b in
    let (nst, b) = Record.recordPacketOut st.write_s.epoch st.write_s.record pv rg Handshake frag_out in
    let wst = {st.write_s with record = nst} in
    let st = {st with write_s = wst} in
   
    let fsh = { nullFServerHello with 
                pv = pv;
                rand = sr;
                sid = sid;
                suite = cs;
                comp = comp;
                ext = ext;
                payload = b;
    } in
    match Tcp.write ns b with
    | Error(x) -> failwith x
    | Correct() -> (st,si,fsh)
