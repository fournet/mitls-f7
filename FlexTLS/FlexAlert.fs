#light "off"

module FlexAlert

open Bytes
open Alert
open Error
open TLSInfo
open TLSError
open TLSConstants

open FlexTypes
open FlexRecord




type FlexAlert = 
    class
    
    (* Receive an expected ServerHelloDone message from the network stream *)
    static member receive (st:state) : state * alertDescription =
        
        let ns = st.ns in
        let buf = st.read.alert_buffer in
        if length buf < 2 then
            let ct,pv,len = FlexRecord.parseFragmentHeader st in
            match ct with
            | Alert -> 
                let st,b = FlexRecord.getFragmentContent (st, ct, len) in
                let buf = buf @| b in
                let st = updateIncomingAlertBuffer st buf in
                FlexAlert.receive st
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "Unexpected content type")
        else
            let alb,rem = Bytes.split buf 2 in
            match Alert.parseAlert alb with
            | Error(ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(ad) ->
                let st = updateIncomingAlertBuffer st rem in
                (st,ad)

    (*
    (* Send ServerHelloDone message to the network stream *)
    static member send (st:state) (si:SessionInfo) (ad:alertDescription) : state * bytes =
    
        let ns = st.ns in
        let msgb = alertBytes ad in

        let len = length msgb in
        let rg : Range.range = (len,len) in

        let id = TLSInfo.id st.write_s.epoch in
        let frag = TLSFragment.fragment id Alert rg msgb in
        let nst,b = Record.recordPacketOut st.write_s.epoch st.write_s.record si.protocol_version rg Alert frag in
        let wst = {st.write_s with record = nst} in
        let st = {st with write_s = wst} in

        let fal = { fal with payload = b } in

        match Tcp.write ns b with
        | Error(x) -> failwith x
        | Correct() -> st,fshd
    *)
    
    end
