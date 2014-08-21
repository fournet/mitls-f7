#light "off"

module FlexFinished

open Tcp
open Bytes
open Error
open TLSInfo
open TLSConstants
open HandshakeMessages

open FlexTypes
open FlexFragment



type FlexFinished = 
    class

    (* Receive an expected Finished message from the network stream *)
    static member receive (st:state) : state * FFinished = 
    
        let buf = st.read_s.hs_buffer in
        let st,hstypeb,len,payload,to_log,buf = FlexFragment.getHSMessage st buf in
    
        match parseHt hstypeb with
        | Error (ad,x) -> failwith x
        | Correct(hst) ->
            match hst with
            | HT_finished  -> 
                if length payload <> 0 then
                    failwith "recvFinished : payload has not length zero"
                else
                    let read_s = {st.read_s with hs_buffer = buf } in
                    let st = {st with read_s = read_s } in
                    let ff = {  nullFFinished with
                                verify_data = payload; 
                                payload = to_log;
                             } in
                    st,ff
            | _ -> failwith "recvFinished : message type is not HT_finished"


    (* Send Finished message to the network stream *)
    static member send (st:state, si:SessionInfo, ?off:FFinished) : state * FFinished =
    
        let ns = st.ns in

        let ff = defaultArg off nullFFinished in

        let msgb = messageBytes HT_finished ff.verify_data in
        let len = length msgb in
        let rg : Range.range = (len,len) in

        let id = TLSInfo.id st.write_s.epoch in
        let frag = TLSFragment.fragment id Handshake rg msgb in
        let nst,b = Record.recordPacketOut st.write_s.epoch st.write_s.record si.protocol_version rg Handshake frag in
        let wst = {st.write_s with record = nst} in
        let st = {st with write_s = wst} in

        let ff = {  ff with 
                    verify_data = msgb;
                    payload = b;
                 } in

        match Tcp.write ns b with
        | Error(x) -> failwith x
        | Correct() -> st,ff

    end
    