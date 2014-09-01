#light "off"

module FlexAppData

open Bytes
open Error
open TLSConstants

open FlexTypes
open FlexRecord

type FlexAppData =
    class

    static member receive(st:state) : state * bytes =
        let ct,pv,len = FlexRecord.parseFragmentHeader st in
        match ct with
        | Application_data ->
            FlexRecord.getFragmentContent(st,ct,len)
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Unexpected content type: %A" ct))

    end