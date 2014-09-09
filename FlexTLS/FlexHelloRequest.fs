#light "off"

module FlexHelloRequest

open Tcp
open Bytes
open Error
open HandshakeMessages
open TLSInfo
open TLSConstants

open FlexTypes
open FlexConstants
open FlexHandshake




type FlexHelloRequest = 
    class

    (* Receive an expected HelloRequest message from the network stream *)
    static member receive (st:state) : state * FHelloRequest = 
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_hello_request  ->         
            if length payload <> 0 then
                failwith (perror __SOURCE_FILE__ __LINE__ "payload has not length zero")
            else
                let fhr = {FlexConstants.nullFHelloRequest with payload = to_log} in
                st,fhr
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "message is not of type HelloRequest")


    (* Send HelloRequest message to the network stream *)
    static member send (st:state, ?fp:fragmentationPolicy) : state * FHelloRequest =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let ns = st.ns in
        let payload = HandshakeMessages.messageBytes HT_hello_request empty_bytes in
        let st = FlexHandshake.send(st,payload,fp) in
        st,{payload = payload}

    end
