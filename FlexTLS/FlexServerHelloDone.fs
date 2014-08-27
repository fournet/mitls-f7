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
                failwith "recvServerHelloDone : payload has not length zero"
            else
                let fshd = {nullFServerHelloDone with payload = to_log} in
                st,fshd
        | _ -> failwith "recvServerHelloDone : message type is not HT_server_hello_done"


    (* Send ServerHelloDone message to the network stream *)
    static member send (st:state, ?fp:fragmentationPolicy) : state * FServerHelloDone =
        // TODO : check that ServerHelloDone doesn't update the nextSecurityContext
        let fp = defaultArg fp defaultFragmentationPolicy in
        let st = FlexHandshake.send(st,HT_server_hello_done,empty_bytes,fp) in
        let fshd = {nullFServerHelloDone with payload = empty_bytes} in
        st,fshd

    end
