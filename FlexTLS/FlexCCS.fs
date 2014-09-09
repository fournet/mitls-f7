#light "off"

module FlexCCS

open Error
open TLSConstants

open FlexTypes
open FlexConstants
open FlexState
open FlexRecord




type FlexCCS =
    class
    
    (* Receive function for handshake ChangeCipherSpecs message *)
    static member receive (st:state) : state * FChangeCipherSpecs =
        let ct,pv,len = FlexRecord.parseFragmentHeader st in
        match ct with
        | Change_cipher_spec ->
            (match len with
            | 1 ->
                let st,payload = FlexRecord.getFragmentContent(st,Change_cipher_spec,1) in
                if payload = HandshakeMessages.CCSBytes then
                    st,{payload = payload }
                else
                    failwith (perror __SOURCE_FILE__ __LINE__ "Unexpected CCS content")
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Unexpected CCS length: %d" len)))
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Unexpected content type: %A" ct))

    (* Send function for handshake ChangeCipherSpecs message *)
    static member send (st:state, ?fccs:FChangeCipherSpecs) : state * FChangeCipherSpecs =
        let fccs = defaultArg fccs FlexConstants.nullFChangeCipherSpecs in
        let record_write,_ = FlexRecord.send(
                st.ns, st.write.epoch, st.write.record,
                Change_cipher_spec, fccs.payload,
                st.write.epoch_init_pv) in
        let st = FlexState.updateOutgoingRecord st record_write in
        st,fccs

    end
