#light "off"

module FlexHelloRequest

open Tcp
open Bytes
open Error
open HandshakeMessages
open TLSInfo
open TLSConstants
open FlexTypes


(* TODO : Receive HelloRequest message *)

(* Send HelloRequest message to the network stream *)
let sendHelloRequest (ns:NetworkStream) (st:state) (cfg:config) =
    
    let b = messageBytes HT_hello_request empty_bytes in
    let len = length b in
    let rg : Range.range = (len,len) in

    let id = TLSInfo.id st.write_s.epoch in
    let frag_out = TLSFragment.fragment id Handshake rg b in
    let (nst, b) = Record.recordPacketOut st.write_s.epoch st.write_s.record cfg.maxVer rg Handshake frag_out in
    let wst = {st.write_s with record = nst} in
    let st = {st with write_s = wst} in

    match Tcp.write ns b with
    | Error(x) -> failwith x
    | Correct() -> st
