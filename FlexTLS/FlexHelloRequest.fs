#light "off"

module FlexHelloRequest

open Tcp
open Bytes
open Error
open HandshakeMessages
open TLSInfo
open TLSConstants

open FlexTypes
open FlexFragment




type FlexHelloRequest = 
    class

    (* Receive an expected HelloRequest message from the network stream *)
    static member receive (st:state) : state * FHelloRequest = 
        
        let st,hstype,payload,to_log = FlexFragment.getHSMessage(st) in
        match hstype with
        | HT_hello_request  ->         
            if length payload <> 0 then
                failwith "recvHelloRequest : payload has not length zero"
            else
                let fhr = {nullFHelloRequest with payload = to_log} in
                st,fhr
        | _ -> failwith "recvHelloRequest : message is not of type HelloRequest"


    (* Send HelloRequest message to the network stream *)
    static member send (st:state) (si:SessionInfo) : state * FHelloRequest =
    
        let ns = st.ns in
        let msgb = messageBytes HT_hello_request empty_bytes in
        let len = length msgb in
        let rg : Range.range = (len,len) in

        let id = TLSInfo.id st.write.epoch in
        let frag_out = TLSFragment.fragment id Handshake rg msgb in
        let nst,b = Record.recordPacketOut st.write.epoch st.write.record si.protocol_version rg Handshake frag_out in
        let wst = {st.write with record = nst} in
        let st = {st with write = wst} in

        let fhr = {nullFHelloRequest with payload = b} in

        match Tcp.write ns b with
        | Error(x) -> failwith x
        | Correct() -> st,fhr
    
    end
