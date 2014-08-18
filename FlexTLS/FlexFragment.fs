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

(* Update incoming state *)
let updateIncomingState (st:state) (incoming:Record.recvState) : state =
    let read_s = {st.read_s with record = incoming} in
    {st with read_s = read_s}


(* Update outgoing state *)
let updateOutgoingState (st:state) (outgoing:Record.sendState) : state =
    let write_s = {st.write_s with record = outgoing} in
    {st with write_s = write_s}

(* Take NS and read the rest of the fragment, then parse to update state and return the rest as bytes *)
let getFragmentContent (ns:NetworkStream) (ct:ContentType) (len:int) (st:state) : state * bytes = 
    match Tcp.read ns len with
    | Error x         -> failwith "Tcp.read len bytes failed"
    | Correct payload ->
        match Record.recordPacketIn st.read_s.epoch st.read_s.record ct payload with
        | Error (ad,x)  -> failwith x
        | Correct (rec_in,rg,frag)  ->
            let st = updateIncomingState st rec_in in
            let id = TLSInfo.id st.read_s.epoch in
            let b = TLSFragment.reprFragment id ct rg frag in
            (st,b)

(* Parse the Handshake message header and get hstype as bytes and length of payload as int *)
let parseHSMessageHeader (buf:bytes) : bytes * int =
    if length buf >= 4 then
        let (hstypeb,rem) = Bytes.split buf 1 in
        let (lenb,rem) = Bytes.split rem 3 in
        let len = Bytes.int_of_bytes lenb in
        (hstypeb,len)
    else    
        failwith "Buffer to small to have a HSMessage header inside"

(* Get Handshake message payload from the buffer and returns it with the remainder of the buffer *)
let splitHSMessage (buf:bytes) : bytes * bytes * bytes * bytes * bytes =
    let (hstypeb,rem) = Bytes.split buf 1 in
    let (lenb,rem2) = Bytes.split rem 3 in
    match HandshakeMessages.parseHt hstypeb with
        | Error (ad,z) ->  failwith z
        | Correct(hstype) -> 
            match vlsplit 3 rem with
            | Error (ad,z) -> failwith z
            | Correct(payload,rem) -> 
                let to_log = hstypeb @| lenb @| payload in 
                (hstypeb,lenb,payload,to_log,rem)

(* Get Handshake message from the fragments and return the state *)
let rec getHSMessage (ns:NetworkStream) (st:state) (buf:bytes) : state * bytes * int * bytes * bytes * bytes =

    if length buf < 4 then
        let ct,pv,len = parseFragmentHeader ns in
        match ct with
        | Handshake -> 
            let st,b = getFragmentContent ns ct len st in
            let buf = buf @| b in
            getHSMessage ns st buf
        | _ -> failwith "parseHSMessage : cannot parse HS message if content type is not Handshake"
    else
        let mt,len = parseHSMessageHeader buf in
        if length buf < len then 
            let ct,pv,len = parseFragmentHeader ns in
            match ct with
            | Handshake -> 
                let st,b = getFragmentContent ns ct len st in
                let buf = buf @| b in
                getHSMessage ns st buf
            | _ -> failwith "parseHSMessage : cannot parse HS message if content type is not Handshake"
        else
            let (hstypeb,lenb,payload,to_log,rem) = splitHSMessage buf in
            (st,hstypeb,len,payload,to_log,rem)
