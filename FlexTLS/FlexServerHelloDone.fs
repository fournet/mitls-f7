#light "off"

module FlexServerHelloDone

open Tcp
open Bytes
open Error
open TLSInfo
open TLSConstants
open HandshakeMessages

open FlexTypes
open FlexRecord




type FlexServerHelloDone = 
    class

    (* Receive an expected ServerHelloDone message from the network stream *)
    static member receive (st:state) : state * FServerHelloDone =
        
        let st,hstype,payload,to_log = FlexRecord.getHSMessage(st) in
        match hstype with
        | HT_server_hello_done  -> 
            if length payload <> 0 then
                failwith "recvServerHelloDone : payload has not length zero"
            else
                let fshd = {nullFServerHelloDone with payload = to_log} in
                st,fshd
        | _ -> failwith "recvServerHelloDone : message type is not HT_server_hello_done"


    (* Send ServerHelloDone message to the network stream *)
    static member send (st:state) (si:SessionInfo) : state * FServerHelloDone =
    
        let ns = st.ns in
        let msgb = messageBytes HT_server_hello_done empty_bytes in
        let len = length msgb in
        let rg : Range.range = (len,len) in

        let id = TLSInfo.id st.write.epoch in
        let frag = TLSFragment.fragment id Handshake rg msgb in
        let nst,b = Record.recordPacketOut st.write.epoch st.write.record si.protocol_version rg Handshake frag in
        let wst = {st.write with record = nst} in
        let st = {st with write = wst} in

        let fshd = {nullFServerHelloDone with payload = b} in

        match Tcp.write ns b with
        | Error(x) -> failwith x
        | Correct() -> st,fshd

    end
