#light "off"

module FlexHandshake

open Bytes
open Error
open TLSConstants

open FlexTypes
open FlexConstants
open FlexState
open FlexRecord



type FlexHandshake =
    class

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
        let buf = st.read.hs_buffer in
        match FlexHandshake.parseHSMessage buf with
        | Error(_) ->
            (let ct,pv,len = FlexRecord.parseFragmentHeader st in
            match ct with
            | Handshake -> 
                let st,b = FlexRecord.getFragmentContent (st, ct, len) in
                let buf = buf @| b in
                let st = FlexState.updateIncomingHSBuffer st buf in
                FlexHandshake.getHSMessage st
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Unexpected content type: %A" ct)))
        | Correct(hst,payload,to_log,rem) ->
                let st = FlexState.updateIncomingHSBuffer st rem in
                (st,hst,payload,to_log)

    (* Forward handshake message *)
    static member forwardHSMessage (stin:state, stout:state) : state * state * bytes =
        let stin,_,_,msg = FlexHandshake.getHSMessage(stin) in
        let stout = FlexHandshake.send(stout,msg) in
        stin,stout,msg

    (* Send handshake message *)
    static member send (st:state, payload:bytes, ?fp:fragmentationPolicy) : state =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let buf = st.write.hs_buffer @| payload in
        let st = FlexState.updateOutgoingHSBuffer st buf in
        FlexRecord.send(st,Handshake,fp)

    end