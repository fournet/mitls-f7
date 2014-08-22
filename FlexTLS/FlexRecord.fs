#light "off"

module FlexRecord

open Tcp
open Bytes
open Error
open TLSInfo
open TLSConstants

open FlexTypes




(* Update incoming record state *)
let updateIncomingRecord (st:state) (incoming:Record.recvState) : state =
    let read_s = {st.read with record = incoming} in
    {st with read = read_s}

let updateIncomingHSBuffer (st:state) buf: state =
    let read_s = {st.read with hs_buffer = buf} in
    {st with read = read_s}

let updateIncomingAlertBuffer (st:state) buf: state =
    let read_s = {st.read with alert_buffer = buf} in
    {st with read = read_s}

(* Update outgoing record state *)
let updateOutgoingRecord (st:state) (outgoing:Record.sendState) : state =
    let write_s = {st.write with record = outgoing} in
    {st with write = write_s}




type FlexRecord = 
    class

    (* Read a record fragment header to get ContentType, ProtocolVersion and Length of the fragment *)
    static member parseFragmentHeader (st:state) : ContentType * ProtocolVersion * nat =
        let ns = st.ns in
        match Tcp.read ns 5 with
        | Error x        -> failwith (perror __SOURCE_FILE__ __LINE__ x)
        | Correct header ->
            match Record.parseHeader header with
            | Error (ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(res) -> res

    (* Reads and decrypts a fragment. Return the updated (decryption) state and the decrypted plaintext *)
    static member getFragmentContent (st:state,ct:ContentType,len:int) : state * bytes = 
        let ns = st.ns in
        match Tcp.read ns len with
        | Error x         -> failwith (perror __SOURCE_FILE__ __LINE__ x)
        | Correct payload ->
            match Record.recordPacketIn st.read.epoch st.read.record ct payload with
            | Error (ad,x)  -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (rec_in,rg,frag)  ->
                let st = updateIncomingRecord st rec_in in
                let id = TLSInfo.id st.read.epoch in
                let b = TLSFragment.reprFragment id ct rg frag in
                (st,b)

    end
