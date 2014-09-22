﻿#light "off"

module FlexAlert

open Bytes
open Alert
open Error
open TLSError
open TLSConstants

open FlexTypes
open FlexConstants
open FlexState
open FlexRecord




type FlexAlert = 
    class
    
    /// <summary>
    /// Receive an Alert message from the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <returns> Updated state * parsed alert description * alert bytes </returns>
    static member receive (st:state) : state * alertDescription * bytes =
        let ns = st.ns in
        let buf = st.read.alert_buffer in
        if length buf < 2 then
            let ct,pv,len,_ = FlexRecord.parseFragmentHeader st in
            match ct with
            | Alert -> 
                let st,b = FlexRecord.getFragmentContent (st, ct, len) in
                let buf = buf @| b in
                let st = FlexState.updateIncomingAlertBuffer st buf in
                FlexAlert.receive st
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Unexpected content type: %A" ct))
        else
            let alb,rem = Bytes.split buf 2 in
            match Alert.parseAlert alb with
            | Error(ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(ad) ->
                let st = FlexState.updateIncomingAlertBuffer st rem in
                (st,ad,alb)

    /// <summary>
    /// Forward an Alert message received from a network stream 
    /// </summary>
    /// <param name="stin"> State of the current Handshake on the incoming side </param>
    /// <param name="stout"> State of the current Handshake on the outgoing side </param>
    /// <param name="fp"> Optional fragmentation policy applied to the message </param>
    /// <returns> Updated incoming state * Updated outgoing state * forwarded alert bytes </returns>
    static member forward (stin:state, stout:state, ?fp:fragmentationPolicy) : state * state * bytes =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let stin,ad,alb = FlexAlert.receive(stin) in
        let stout   = FlexAlert.send(stout,alb,fp) in
        stin,stout,alb

    /// <summary>
    /// Send an Alert message to the network stream 
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="ad"> Alert description union type already parsed </param>
    /// <param name="fp"> Optional fragmentation policy applied to the message </param>
    /// <returns> Updated state </returns>
    static member send (st:state, ad:alertDescription, ?fp:fragmentationPolicy) : state =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        FlexAlert.send(st, alertBytes ad, fp)

    /// <summary>
    /// Send an Alert message to the network stream 
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="payload"> Alert bytes </param>
    /// <param name="fp"> Optional fragmentation policy applied to the message </param>
    /// <returns> Updated state </returns>
    static member send (st:state, payload:bytes, ?fp:fragmentationPolicy) : state =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let buf = st.write.alert_buffer @| payload in
        let st = FlexState.updateOutgoingAlertBuffer st buf in
        FlexRecord.send(st,Alert,fp)
    
    end
