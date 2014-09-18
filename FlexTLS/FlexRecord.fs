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
    | Application_data -> ch.appdata_buffer
    | _ -> failwith "Unsupported content type"




type FlexRecord = 
    class

    (* Read a record fragment header to get ContentType, ProtocolVersion and Length of the fragment *)
    static member parseFragmentHeader (st:state) : ContentType * ProtocolVersion * nat * bytes =
        let ns = st.ns in
        match Tcp.read ns 5 with
        | Error x        -> failwith (perror __SOURCE_FILE__ __LINE__ x)
        | Correct header ->
            match Record.parseHeader header with
            | Error (ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(ct,pv,len) -> ct,pv,len,header

    (* Reads and decrypts a fragment. Return the updated (decryption) state and the decrypted plaintext *)
    static member getFragmentContent (st:state, ct:ContentType, len:int) : state * bytes = 
        let ns = st.ns in
        match Tcp.read ns len with
        | Error x         -> failwith (perror __SOURCE_FILE__ __LINE__ x)
        | Correct payload ->
            match Record.recordPacketIn st.read.epoch st.read.record ct payload with
            | Error (ad,x)  -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (rec_in,rg,frag)  ->
                let st = FlexState.updateIncomingRecord st rec_in in
                let id = TLSInfo.id st.read.epoch in
                let fragb = TLSFragment.reprFragment id ct rg frag in
                (st,fragb)

    static member encrypt (e:epoch, pv:ProtocolVersion, k:Record.ConnectionState, ct:ContentType, payload:bytes) : Record.ConnectionState * bytes =
        // pv is the protocol version set in the record header.
        // For encrypting epochs, it'd better match the protocol version contained in the epoch, since the latter is used for the additional data
        let len = length payload in
        let rg : Range.range = (len,len) in
        let id = TLSInfo.id e in
        let frag = TLSFragment.fragment id ct rg payload in
        let k,b = Record.recordPacketOut e k pv rg ct frag in
        (k,b)

    (* Forward a record *)
    static member forward (stin:state, stout:state, ?fp:fragmentationPolicy) : state * state * bytes =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let ct,pv,len,header = FlexRecord.parseFragmentHeader(stin) in
        let stin,payload = FlexRecord.getFragmentContent(stin,ct,len) in
        let k,_ = FlexRecord.send(stout.ns,stout.write.epoch,stout.write.record,ct,payload,stout.write.epoch_init_pv,fp) in
        let stout = FlexState.updateOutgoingRecord stout k in
        stin,stout,payload

    (* Send genric method based on content type and state *)
    static member send (st:state, ct:ContentType, ?fp:fragmentationPolicy) : state =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let payload = pickCTBuffer st.write ct in
        let k,rem = FlexRecord.send(st.ns,st.write.epoch,st.write.record,ct,payload,st.write.epoch_init_pv,fp) in
        let st = FlexState.updateOutgoingBuffer st ct rem in
        let st = FlexState.updateOutgoingRecord st k in
        st

    (* Send data over the network after encrypting a record depending on the fragmentation policy *)
    static member send (ns:NetworkStream, e:epoch, k:Record.ConnectionState, ct:ContentType, payload:bytes, ?epoch_init_pv:ProtocolVersion, ?fp:fragmentationPolicy) : Record.ConnectionState * bytes =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let pv = 
            if TLSInfo.isInitEpoch e then
                match epoch_init_pv with
                | None -> failwith (perror __SOURCE_FILE__ __LINE__ "A protocol version value must be provided for the initial epoch")
                | Some(pv) -> pv
            else
                let si = TLSInfo.epochSI e in
                si.protocol_version
        in
        let msgb,rem = splitCTPayloadFP payload fp in
        let k,b = FlexRecord.encrypt (e,pv,k,ct,msgb) in
        match Tcp.write ns b with
        | Error x -> failwith x
        | Correct() -> 
            match fp with
            | All(fs) -> 
                if rem = empty_bytes then
                    (k,rem)
                else
                    FlexRecord.send(ns,e,k,ct,rem,pv,fp)
            | One(fs) -> (k,rem)
                
    end
