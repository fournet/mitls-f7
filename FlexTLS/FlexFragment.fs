#light "off"

module FlexFragment

open Tcp
open Bytes
open Error
open TLSConstants

open FlexTypes


(* Take NS and read fragment Header to get ContentType, ProtocolVersion and Length of the fragment *)
let parseFragmentHeader (ns:NetworkStream) : ContentType * ProtocolVersion * nat =
    match Tcp.read ns 5 with
    | Error x        -> failwith "Tcp.read header 5 bytes failed"
    | Correct header ->
        match Record.parseHeader header with
        | Error x      -> failwith (sprintf "%A" x)
        | Correct(res) -> res

(* Take NS and read the rest of the fragment, then parse to update state and return the rest as raw fragment *)
let getFragmentContent (ns:NetworkStream) (ct:ContentType) (len:int) (st:state) = 
    match Tcp.read ns len with
    | Error x         -> failwith "Tcp.read len bytes failed"
    | Correct payload ->
        Record.recordPacketIn st.read_s.epoch st.read_s.record ct payload



(* TODO : Create a function getHSMessage *)
(* TODO : Create a toplevel getMessage patternmatching on CT *)
