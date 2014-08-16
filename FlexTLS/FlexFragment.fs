#light "off"

module FlexFragment

open Tcp
open Bytes
open Error
open TLSInfo
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

(* Upgrade state and get the new id*)
let updateIncomingStateANDgetNewId (st:state) (incoming:Record.recvState) : state * TLSInfo.id =
        let read_s = {st.read_s with record = incoming} in
        let st = {st with read_s = read_s} in
        let id = TLSInfo.id st.read_s.epoch in
        (st,id)

(* Get Handshake message from the fragment and return message bytes *)
let getHSMessage (st:state) (id:TLSInfo.id) (ct:ContentType) (rg:Range.range) (frag:TLSFragment.fragment) =
        
        (* !!! Something is really wrong here !!! *)

        (* let hsstate = { state with hs_incoming = rem } in
        let b = Handshake.recv_oneHSFragment 
        match parseMessageState ci state with
        | Error(err) -> failwith err
        | Correct(state,hstype,payload,to_log) ->
        *)

        let b = TLSFragment.reprFragment id ct rg frag in
        let history = Record.history st.read_s.epoch Reader st.read_s.record in
        let f = TLSFragment.RecordPlainToHSPlain st.read_s.epoch history rg frag in
        HSFragment.fragmentRepr id rg f


(* TODO : Create a toplevel getMessage patternmatching on CT *)
