#light "off"

module FlexServerHelloDone

open Tcp
open Bytes
open Error
open HandshakeMessages
open TLSInfo
open TLSConstants

open FlexTypes
open FlexFragment




(* Receive an expected ServerHelloDone message from the network stream *)
let recvServerHelloDone (ns:NetworkStream) (st:state) (cfg:config) : state * FServerHelloDone = 
    
    let ct,pv,len = parseFragmentHeader ns in
    let st,buf = getFragmentContent ns ct len st in
    
    let st,hstypeb,len,payload,to_log,rem = getHSMessage ns st buf in
    match cbyte hstypeb with
    | 14uy  ->         
        if length payload <> 0 then
            failwith "recvServerHelloDone : payload has not length zero"
        else
            let fshd = {nullFServerHelloDone with fshd_null_payload = payload} in
            st,fshd
    | _ -> failwith "recvServerHelloDone : message is not of type ServerHelloDone"


(* Send ServerHelloDone message to the network stream *)
let sendServerHelloDone (ns:NetworkStream) (st:state) (cfg:config) : state * FServerHelloDone =
    
    let b = messageBytes HT_server_hello_done empty_bytes in
    let len = length b in
    let rg : Range.range = (len,len) in

    let id = TLSInfo.id st.write_s.epoch in
    let frag_out = TLSFragment.fragment id Handshake rg b in
    let (nst, b) = Record.recordPacketOut st.write_s.epoch st.write_s.record cfg.maxVer rg Handshake frag_out in
    let wst = {st.write_s with record = nst} in
    let st = {st with write_s = wst} in

    let fshd = {nullFServerHelloDone with fshd_null_payload = empty_bytes} in

    match Tcp.write ns b with
    | Error(x) -> failwith x
    | Correct() -> st,fshd
