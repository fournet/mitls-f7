#light "off"

module FlexCCS

open Bytes
open Error
open TLSConstants

open FlexTypes
open FlexConstants
open FlexState
open FlexRecord




type FlexCCS =
    class
    
    /// <summary>
    /// Receive ChangeCipherSpecs message from network stream 
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <returns> Updated state * CCS record * CCS byte </returns>
    static member receive (st:state) : state * FChangeCipherSpecs * bytes =
        let ct,pv,len,_ = FlexRecord.parseFragmentHeader st in
        match ct with
        | Change_cipher_spec ->
            (match len with
            | 1 ->
                let st,payload = FlexRecord.getFragmentContent(st,Change_cipher_spec,1) in
                if payload = HandshakeMessages.CCSBytes then
                    st,{payload = payload },payload
                else
                    failwith (perror __SOURCE_FILE__ __LINE__ "Unexpected CCS content")
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Unexpected CCS length: %d" len)))
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Unexpected content type: %A" ct))

    /// <summary>
    /// Forward CCS to the network stream 
    /// </summary>
    /// <param name="stin"> State of the current Handshake on the incoming side </param>
    /// <param name="stout"> State of the current Handshake on the outgoing side </param>
    /// <returns> Updated incoming state * Updated outgoing state * forwarded CCS byte </returns>
    static member forward (stin:state, stout:state) : state * state * bytes =
        let stin,ccs,msgb  = FlexCCS.receive(stin) in
        let stout,_ = FlexCCS.send(stout) in
        let msgb = ccs.payload in
        stin,stout,msgb

    /// <summary>
    /// Send CCS to the network stream 
    /// </summary>
    /// <param name="st"> State of the current Handshake on the incoming side </param>
    /// <param name="fccs"> Optional CCS message record </param>
    /// <returns> Updated state * CCS message record </returns>
    static member send (st:state, ?fccs:FChangeCipherSpecs) : state * FChangeCipherSpecs =
        let fccs = defaultArg fccs FlexConstants.nullFChangeCipherSpecs in
        let record_write,_ = FlexRecord.send(
                st.ns, st.write.epoch, st.write.record,
                Change_cipher_spec, fccs.payload,
                st.write.epoch_init_pv) in
        let st = FlexState.updateOutgoingRecord st record_write in
        st,fccs

    end
