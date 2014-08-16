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


(* TODO : Since peer is not suppose to know if a HelloRequest will be received we have to have a Wait function *)


(* (* Receive an expected HelloRequest message from the network stream *)
let recvHelloRequest (ns:NetworkStream) (st:state) (cfg:config) =
    
    let ct,pv,len = parseFragmentHeader ns in

        match getFragmentContent ns ct len st with
        | Error (ad,x) -> failwith x
        | Correct (rec_in,rg,frag)  ->
            let read_s = {st.read_s with record = rec_in} in
            let st = {st with read_s = read_s} in
            let id = TLSInfo.id st.read_s.epoch in
            let history = Record.history st.read_s.epoch Reader st.read_s.record in
          
            let f = TLSFragment.RecordPlainToHSPlain st.read_s.epoch history rg frag in
            let b = HSFragment.fragmentRepr id rg f in 

            match HandshakeMessages.parseH b with
            | Error (ad,x) -> failwith x
            | Correct (certC) -> 
*)

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
