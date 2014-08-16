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

open FlexTypes
open FlexFragment




(* Receive a ServerHello message from the network stream *)
let recvServerHello (ns:NetworkStream) (st:state) (si:SessionInfo) : state * SessionInfo * FServerHello =
    
    let ct,pv,len = parseFragmentHeader ns in

    match getFragmentContent ns ct len st with
    | Error (ad,x)  -> failwith x
    | Correct (rec_in,rg,frag)  ->
        let st,id = updateIncomingStateANDgetNewId st rec_in in
        let b = getHSMessage st id ct rg frag in

        match HandshakeMessages.parseServerHello b with
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
                        payload = b;
            } in
            (st,si,fsh)
        
        
        
(* Send a ServerHello message from the network stream *)
let sendServerHello (ns:NetworkStream) (st:state) (si:SessionInfo) (sh:FServerHello) : state * SessionInfo * FServerHello =
    
    let pv = sh.pv in
    let cs = sh.suite in
    let comp = sh.comp in
    let ext = sh.ext in
    let sid = empty_bytes in
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
