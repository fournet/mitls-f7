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
    static member receive (st:state, ?nsc:nextSecurityContext) : state * nextSecurityContext * FChangeCipherSpecs =
        let nsc = defaultArg nsc nullNextSecurityContext in
        let st,payload = FlexRecord.getFragmentContent(st,Change_cipher_spec,1) in
        let fccs = 
            if payload = HandshakeMessages.CCSBytes then
                {nullFChangeCipherSpecs with payload = payload }
            else
                failwith (perror __SOURCE_FILE__ __LINE__ "ChangeCipherSpecs message is not correct")
        in
        st,nsc,fccs

    (* Send function for handshake ChangeCipherSpecs message *)
    static member send (st:state, ?nsc:nextSecurityContext, ?fp:fragmentationPolicy) : state * nextSecurityContext * FChangeCipherSpecs =
        let fp = defaultArg fp defaultFragmentationPolicy in
        let nsc = defaultArg nsc nullNextSecurityContext in 
        let st = FlexRecord.send(st,Change_cipher_spec,fp) in
        let fccs = {nullFChangeCipherSpecs with payload = ccs_buffer } in
        st,nsc,fccs

    end
