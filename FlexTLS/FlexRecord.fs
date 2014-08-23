#light "off"

module FlexRecord

open Tcp
open Bytes
open Error
open TLSInfo
open TLSConstants

open FlexTypes
open FlexConstants
open FlexState




(* Get fragment length depending on the fragmentation policy *)
let fs_of_fp fp =
    match fp with
    | All(n) | One(n) -> n

(* Split any CT payload data depending on the fragmentation size *)
let splitCTPayloadFP (b:bytes) (fp:fragmentationPolicy) : bytes * bytes =
    let len = System.Math.Min((length b),(fs_of_fp fp)) in
    Bytes.split b len

(* Pick a buffer according to corresponding ContentType *)
let pickCTBuffer (ch:channel) (ct:ContentType) : bytes = 
    match ct with
    | Handshake -> ch.hs_buffer
    | Alert -> ch.alert_buffer
    | _ -> failwith "Unsupported content type"



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
                let st = FlexState.updateIncomingRecord st rec_in in
                let id = TLSInfo.id st.read.epoch in
                let b = TLSFragment.reprFragment id ct rg frag in
                (st,b)

    (* Send data over the network after encrypting a record depending on the fragmentation policy *)
    static member sendSpecific (ns:NetworkStream, e:epoch, k:Record.ConnectionState, ct:ContentType, payload:bytes, ?ofp:fragmentationPolicy) : Record.ConnectionState * bytes =
        
        let fp = defaultArg ofp defaultFragmentationPolicy in
        
        (* TODO : Here the user cannot choose the ProtocolVersion if it is an initEpoch, default is set by force while it shouldn't be the case *)
        let pv = 
            if TLSInfo.isInitEpoch e then
                defaultProtocolVersion
            else
                let si = TLSInfo.epochSI e in
                si.protocol_version
        in

        let msgb,rem = splitCTPayloadFP payload fp in
        let len = length msgb in
        let rg : Range.range = (len,len) in
        let id = TLSInfo.id e in
        let frag = TLSFragment.fragment id ct rg msgb in
        let k,b = Record.recordPacketOut e k pv rg ct frag in

        match Tcp.write ns b with
        | Error x -> failwith x
        | Correct() -> 
            match fp with
            | All(fs) -> 
                if rem = empty_bytes then
                    (k,rem)
                else
                    FlexRecord.sendSpecific(ns,e,k,ct,rem,fp)
            | One(fs) -> (k,rem)
                
                

    (* Send genric method based on content type and state *)
    static member send (st:state, ct:ContentType, ?ofp:fragmentationPolicy) : state =
        
        let fp = defaultArg ofp defaultFragmentationPolicy in

        let payload = pickCTBuffer st.write ct in
        let k,rem = FlexRecord.sendSpecific(st.ns,st.write.epoch,st.write.record,ct,payload,fp) in
        let st = FlexState.updateOutgoingHSBuffer st rem in
        let st = FlexState.updateOutgoingRecord st k in
        (st)

    end
