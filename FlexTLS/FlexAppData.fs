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

    static member receive(st:state) : state * bytes =
        let ct,pv,len = FlexRecord.parseFragmentHeader st in
        match ct with
        | Application_data ->
            FlexRecord.getFragmentContent(st,ct,len)
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Unexpected content type: %A" ct))

    static member send(st:state, data:string, ?encoding:System.Text.Encoding, ?fp:fragmentationPolicy): state =
        let fp = defaultArg fp defaultFragmentationPolicy in
        let encoding = defaultArg encoding System.Text.Encoding.ASCII in
        let payload = abytes(encoding.GetBytes(data)) in
        FlexAppData.send(st,payload,fp)

    static member send(st:state, data:bytes, ?fp:fragmentationPolicy): state =
        let fp = defaultArg fp defaultFragmentationPolicy in
        let buf = st.write.appdata_buffer @| data in
        let st = FlexState.updateOutgoingAppDataBuffer st buf in
        FlexRecord.send(st,Application_data,fp)

    end