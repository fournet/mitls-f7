#light "off"

module FlexAlert

open Bytes
open Alert
open Error
open TLSInfo
open TLSError
open TLSConstants

open FlexTypes
open FlexConstants
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

    (* Send alert message *)
    static member send (st:state, ad:alertDescription, msgPayload:bytes, ?ofp:fragmentationPolicy) : state =
        let fp = defaultArg ofp defaultFragmentationPolicy in
        let buf = st.write.alert_buffer @| msgPayload in
        let st = FlexRecord.updateOutgoingAlertBuffer st buf in
        FlexRecord.send(st,Alert,fp)
    
    end
