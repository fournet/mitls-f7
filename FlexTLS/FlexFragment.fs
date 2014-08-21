#light "off"

module FlexFragment

open Tcp
open Bytes
open Error
open TLSInfo
open TLSConstants

open FlexTypes


type FlexFragment = 
    class

    (* Update incoming record state *)
    static member updateIncomingState (st:state) (incoming:Record.recvState) : state =
        let read_s = {st.read_s with record = incoming} in
        {st with read_s = read_s}

    (* Update outgoing record state *)
    static member updateOutgoingState (st:state) (outgoing:Record.sendState) : state =
        let write_s = {st.write_s with record = outgoing} in
        {st with write_s = write_s}

    (* Take NS and read fragment Header to get ContentType, ProtocolVersion and Length of the fragment *)
    static member parseFragmentHeader (st:state) : ContentType * ProtocolVersion * nat =
        let ns = st.ns in
        match Tcp.read ns 5 with
        | Error x        -> failwith "Tcp.read header 5 bytes failed"
        | Correct header ->
            match Record.parseHeader header with
            | Error x      -> failwith (sprintf "%A" x)
            | Correct(res) -> res

    (* Take NS and read the rest of the fragment, then parse to update state and return the rest as bytes *)
    static member getFragmentContent (st:state) (ct:ContentType) (len:int) : state * bytes = 
        let ns = st.ns in
        match Tcp.read ns len with
        | Error x         -> failwith "Tcp.read len bytes failed"
        | Correct payload ->
            match Record.recordPacketIn st.read_s.epoch st.read_s.record ct payload with
            | Error (ad,x)  -> failwith x
            | Correct (rec_in,rg,frag)  ->
                let st = FlexFragment.updateIncomingState st rec_in in
                let id = TLSInfo.id st.read_s.epoch in
                let b = TLSFragment.reprFragment id ct rg frag in
                (st,b)

    (* Parse the Handshake message header and get hstype as bytes and length of payload as int *)
    static member parseHSMessageHeader (buf:bytes) : bytes * int =
        if length buf >= 4 then
            let (hstypeb,rem) = Bytes.split buf 1 in
            let (lenb,rem) = Bytes.split rem 3 in
            let len = Bytes.int_of_bytes lenb in
            (hstypeb,len)
        else    
            failwith "Buffer to small to have a HSMessage header inside"

    (* Get Alert message from the buffer and return the state *)
    static member getAlertMessage (st:state) (buf:bytes) : state * bytes * bytes =
        let ns = st.ns in
        if length buf < 2 then
            let ct,pv,len = FlexFragment.parseFragmentHeader st in
            match ct with
            | Alert -> 
                let st,b = FlexFragment.getFragmentContent st ct len in
                let buf = buf @| b in
                FlexFragment.getAlertMessage st buf
            | _ -> failwith "getAlertMessage : cannot parse Alert message if content type is not Alert"
        else
            let alb,rem = Bytes.split buf 2 in
            (st,alb,rem)
            

    (* Split Handshake message payload from the buffer and returns it with the hstype, length, to_log and remainder of the buffer as bytes*)
    static member splitHSMessage (buf:bytes) : bytes * bytes * bytes * bytes * bytes =
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

    (* Get Handshake message from the buffer and return the state *)
    static member getHSMessage (st:state) (buf:bytes) : state * bytes * int * bytes * bytes * bytes =
        let ns = st.ns in
        if length buf < 4 then
            let ct,pv,len = FlexFragment.parseFragmentHeader st in
            match ct with
            | Handshake -> 
                let st,b = FlexFragment.getFragmentContent st ct len in
                let buf = buf @| b in
                FlexFragment.getHSMessage st buf
            | _ -> failwith "parseHSMessage : cannot parse HS message if content type is not Handshake"
        else
            let mt,len = FlexFragment.parseHSMessageHeader buf in
            if length buf < len then 
                let ct,pv,len = FlexFragment.parseFragmentHeader st in
                match ct with
                | Handshake -> 
                    let st,b = FlexFragment.getFragmentContent st ct len in
                    let buf = buf @| b in
                    FlexFragment.getHSMessage st buf
                | _ -> failwith "parseHSMessage : cannot parse HS message if content type is not Handshake"
            else
                let (hstypeb,lenb,payload,to_log,rem) = FlexFragment.splitHSMessage buf in
                (st,hstypeb,len,payload,to_log,rem)

    end
