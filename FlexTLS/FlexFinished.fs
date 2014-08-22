#light "off"

module FlexFinished

open Tcp
open Bytes
open Error
open TLSInfo
open TLSConstants
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexHandshake



type FlexFinished = 
    class

    (* Receive an expected Finished message from the network stream *)
    static member receive (st:state) : state * FFinished = 
        
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_finished  -> 
            if length payload <> 0 then
                failwith "recvFinished : payload has not length zero"
            else
                let ff = {  nullFFinished with
                            verify_data = payload; 
                            payload = to_log;
                            } in
                st,ff
        | _ -> failwith "recvFinished : message type is not HT_finished"


    (* Send Finished message to the network stream *)
    static member send (st:state, nsc:nextSecurityContext, ?off:FFinished) : state * FFinished =
    
        let ns = st.ns in
        let si = nsc.si in
        let ff = defaultArg off nullFFinished in

        let msgb = messageBytes HT_finished ff.verify_data in
        let len = length msgb in
        let rg : Range.range = (len,len) in

        let id = TLSInfo.id st.write.epoch in
        let frag = TLSFragment.fragment id Handshake rg msgb in
        let nst,b = Record.recordPacketOut st.write.epoch st.write.record si.protocol_version rg Handshake frag in
        let wst = {st.write with record = nst} in
        let st = {st with write = wst} in

        let ff = {  ff with 
                    verify_data = msgb;
                    payload = b;
                 } in

        match Tcp.write ns b with
        | Error(x) -> failwith x
        | Correct() -> st,ff

    end
    