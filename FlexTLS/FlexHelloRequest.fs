#light "off"

module FlexHelloRequest

open Tcp
open Bytes
open Error
open HandshakeMessages
open TLSInfo
open TLSConstants

open FlexTypes
open FlexFragment




(* Receive an expected HelloRequest message from the network stream *)
let recvHelloRequest (st:state) (cfg:config) : state * FHelloRequest = 
    
    let buf = st.read_s.buffer in
    let st,hstypeb,len,payload,to_log,rem = getHSMessage st buf in
    
    match parseHt hstypeb with
    | Error (ad,x) -> failwith x
    | Correct(hst) ->
        match hst with
        | HT_hello_request  ->         
            if length payload <> 0 then
                failwith "recvHelloRequest : payload has not length zero"
            else
                let fhr = {nullFHelloRequest with payload = to_log} in
                st,fhr
        | _ -> failwith "recvHelloRequest : message is not of type HelloRequest"


(* Send HelloRequest message to the network stream *)
let sendHelloRequest (st:state) (cfg:config) : state * FHelloRequest =
    
    let ns = st.ns in
    let b = messageBytes HT_hello_request empty_bytes in
    let len = length b in
    let rg : Range.range = (len,len) in

    let id = TLSInfo.id st.write_s.epoch in
    let frag_out = TLSFragment.fragment id Handshake rg b in
    let (nst, b) = Record.recordPacketOut st.write_s.epoch st.write_s.record cfg.maxVer rg Handshake frag_out in
    let wst = {st.write_s with record = nst} in
    let st = {st with write_s = wst} in

    let fhr = {nullFHelloRequest with payload = empty_bytes} in

    match Tcp.write ns b with
    | Error(x) -> failwith x
    | Correct() -> st,fhr
