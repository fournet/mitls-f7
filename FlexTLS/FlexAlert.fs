#light "off"

module FlexAlert

open Alert
open FlexTypes


type FlexAlert = 
    class
    (*
    static member receive (st:state) : state * FAlert =
    (* Receive an expected ServerHelloDone message from the network stream *)
    
        let buf = st.read_s.buffer in
        let st,altypeb,len,payload,to_log,rem = FlexFragment.getAlertMessage st buf in
    
        match Alert.parseAlert altypeb with
        | Error (ad,x) -> failwith x
        | Correct(hst) ->
            match hst with
            | HT_server_hello_done  -> 
                if length payload <> 0 then
                    failwith "recvServerHelloDone : payload has not length zero"
                else
                    let fshd = {nullFServerHelloDone with payload = to_log} in
                    st,fshd
            | _ -> failwith "recvServerHelloDone : message type is not HT_server_hello_done"


    (* Send ServerHelloDone message to the network stream *)
    static member send (st:state) (faf:FAlert) : state * FAlert =
    
        let ns = st.ns in
        let b = messageBytes HT_server_hello_done empty_bytes in
        let len = length b in
        let rg : Range.range = (len,len) in

        let id = TLSInfo.id st.write_s.epoch in
        let frag_out = TLSFragment.fragment id Alert rg b in
        let (nst, b) = Record.recordPacketOut st.write_s.epoch st.write_s.record cfg.maxVer rg Handshake frag_out in
        let wst = {st.write_s with record = nst} in
        let st = {st with write_s = wst} in

        let fshd = {nullFServerHelloDone with payload = empty_bytes} in

        match Tcp.write ns b with
        | Error(x) -> failwith x
        | Correct() -> st,fshd

    *)
    end
