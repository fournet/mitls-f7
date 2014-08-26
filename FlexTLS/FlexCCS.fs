#light "off"

module FlexCCS

open Error
open TLSConstants

open FlexTypes
open FlexConstants
open FlexState
open FlexRecord


// FIXME : The state should be updated by the new security context after receiving and sending the CCS

type FlexCCS =
    class
    
    (* Receive function for handshake ChangeCipherSpecs message *)
    static member receive (st:state, ?nsc:nextSecurityContext) : state * nextSecurityContext * FChangeCipherSpecs =
        let nsc = defaultArg nsc nullNextSecurityContext in
        let st,payload = FlexRecord.getFragmentContent(st,Handshake,1) in
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
        let payload = HandshakeMessages.CCSBytes in
        // TODO : Should we consider CCS part of the Handshake or not ?...
        (* Here I consider it is inside the handshake so I store it in the HS buffer *)
        let st = FlexState.updateOutgoingHSBuffer st payload in
        let st = FlexRecord.send(st,Handshake,fp) in
        let fccs = {nullFChangeCipherSpecs with payload = payload } in
        st,nsc,fccs

    end
