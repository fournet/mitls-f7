#light "off"

module FlexFragment

open Tcp
open Bytes
open Error
open TLSInfo
open TLSConstants

open FlexTypes

(* Update incoming record state *)
let updateIncomingRecord (st:state) (incoming:Record.recvState) : state =
    let read_s = {st.read_s with record = incoming} in
    {st with read_s = read_s}

let updateIncomingHSBuffer (st:state) buf: state =
    let read_s = {st.read_s with hs_buffer = buf} in
    {st with read_s = read_s}

let updateIncomingAlertBuffer (st:state) buf: state =
    let read_s = {st.read_s with alert_buffer = buf} in
    {st with read_s = read_s}

(* Update outgoing record state *)
let updateOutgoingRecord (st:state) (outgoing:Record.sendState) : state =
    let write_s = {st.write_s with record = outgoing} in
    {st with write_s = write_s}

type FlexFragment = 
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
            match Record.recordPacketIn st.read_s.epoch st.read_s.record ct payload with
            | Error (ad,x)  -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (rec_in,rg,frag)  ->
                let st = updateIncomingRecord st rec_in in
                let id = TLSInfo.id st.read_s.epoch in
                let b = TLSFragment.reprFragment id ct rg frag in
                (st,b)

    (* Parse a Handshake message. Return message type, payload, to_log -- that is raw header+payload -- and the remainder of the buffer *)
    static member parseHSMessage (buf:bytes) =
        if length buf >= 4 then
            let (hstypeb,rem) = Bytes.split buf 1 in
            match HandshakeMessages.parseHt hstypeb with
            | Error (_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(hst) ->
                let (lenb,rem) = Bytes.split rem 3 in
                let len = int_of_bytes lenb in
                if length rem < len then
                    Error("Given buffer too small")
                else
                    let (payload,rem) = Bytes.split rem len in
                    let to_log = hstypeb @| lenb @| payload in 
                    Correct (hst,payload,to_log,rem)
        else    
            Error("Given buffer too small")

    (* Get Handshake message from the buffer and return the state *)
    static member getHSMessage st =
        let ns = st.ns in
        let buf = st.read_s.hs_buffer in
        match FlexFragment.parseHSMessage buf with
        | Error(_) ->
            (let ct,pv,len = FlexFragment.parseFragmentHeader st in
            match ct with
            | Handshake -> 
                let st,b = FlexFragment.getFragmentContent (st, ct, len) in
                let buf = buf @| b in
                let st = updateIncomingHSBuffer st buf in
                FlexFragment.getHSMessage st
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "Unexpected content type"))
        | Correct(hst,payload,to_log,rem) ->
                let st = updateIncomingHSBuffer st rem in
                (st,hst,payload,to_log)

    (* Get Alert message from the buffer and return the state *)
    static member getAlertMessage st =
        let ns = st.ns in
        let buf = st.read_s.alert_buffer in
        if length buf < 2 then
            let ct,pv,len = FlexFragment.parseFragmentHeader st in
            match ct with
            | Alert -> 
                let st,b = FlexFragment.getFragmentContent (st, ct, len) in
                let buf = buf @| b in
                let st = updateIncomingAlertBuffer st buf in
                FlexFragment.getAlertMessage st
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "Unexpected content type")
        else
            let alb,rem = Bytes.split buf 2 in
            match Alert.parseAlert alb with
            | Error(ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(ad) ->
                let st = updateIncomingAlertBuffer st rem in
                (st,ad)

    end
