#light "off"

module FlexAppData

open Bytes
open Error
open TLSConstants

open FlexTypes
open FlexConstants
open FlexRecord
open FlexState




type FlexAppData =
    class

    (* Receive application data *)
    static member receive (st:state) : state * bytes =
        let ct,pv,len = FlexRecord.parseFragmentHeader st in
        match ct with
        | Application_data ->
            FlexRecord.getFragmentContent(st,ct,len)
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Unexpected content type: %A" ct))

    (* Forward application data *)
    static member forward (stin:state, stout:state, ?fp:fragmentationPolicy) : state * state * bytes =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let stin,appb = FlexAppData.receive(stin) in
        let stout = FlexAppData.send(stout,appb,fp) in
        stin,stout,appb
    
    (* Send application data from encoded string *)
    static member send(st:state, data:string, ?encoding:System.Text.Encoding, ?fp:fragmentationPolicy): state =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let encoding = defaultArg encoding System.Text.Encoding.ASCII in
        let payload = abytes(encoding.GetBytes(data)) in
        FlexAppData.send(st,payload,fp)

    (* Send application data from raw bytes *)
    static member send(st:state, data:bytes, ?fp:fragmentationPolicy) : state =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let buf = st.write.appdata_buffer @| data in
        let st = FlexState.updateOutgoingAppDataBuffer st buf in
        FlexRecord.send(st,Application_data,fp)

    end