#light "off"

module FlexServerHelloDone

open Tcp
open Bytes
open Error
open TLSInfo
open TLSConstants
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexHandshake




type FlexServerHelloDone = 
    class

    (* Receive an expected ServerHelloDone message from the network stream *)
    static member receive (st:state) : state * FServerHelloDone =
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_server_hello_done  -> 
            if length payload <> 0 then
                failwith (perror __SOURCE_FILE__ __LINE__ "payload has not length zero")
            else
                let fshd: FServerHelloDone = {payload = to_log} in
                st,fshd
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "message type is not HT_server_hello_done")

    (* Prepare ServerHelloDone message bytes *)
    static member prepare (st:state) : bytes * state * FServerHelloDone =
        let payload = HandshakeMessages.serverHelloDoneBytes in
        let fshd: FServerHelloDone = {payload = payload} in
        payload,st,fshd

    (* Send ServerHelloDone message to the network stream *)
    static member send (st:state, ?fp:fragmentationPolicy) : state * FServerHelloDone =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let st = FlexHandshake.send(st,HandshakeMessages.serverHelloDoneBytes,fp) in
        let fshd: FServerHelloDone = {payload = HandshakeMessages.serverHelloDoneBytes} in
        st,fshd

    end
