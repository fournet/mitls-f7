#light "off"

module FlexServerHello

open Tcp
open Bytes
open Error
open System
open System.IO
open TLS
open TLSInfo
open TLSConstants
open TLSExtensions
open HandshakeMessages

open FlexTypes
open FlexFragment




(* Inference on user provided information *)
let fillFServerHelloANDSi (fsh:FServerHello) (si:SessionInfo) : FServerHello * SessionInfo =

    (* rand = Is there random bytes ? If no, create some *)
    let rand =
        match fsh.rand = nullFServerHello.rand with
        | false -> fsh.rand
        | true -> Nonce.mkHelloRandom()
    in

    (* Update fch with correct informations and sets payload to empty bytes *)
    let fsh = { fsh with 
                rand = rand;
                payload = empty_bytes 
              } 
    in

    (* Update si with correct informations from fsh *)
    let si = { si with
               protocol_version = fsh.pv;
               sessionID = fsh.sid;
               cipher_suite = fsh.suite;
               compression = fsh.comp;
               init_srand = fsh.rand;
             } 
    in
    (fsh,si)




type FlexServerHello = 
    class

    (* Receive a ServerHello message from the network stream *)
    static member receive (st:state) (si:SessionInfo) : state * SessionInfo * FServerHello =
    
        let buf = st.read_s.hs_buffer in
        let st,hstypeb,len,payload,to_log,buf = FlexFragment.getHSMessage st buf in
    
        match parseHt hstypeb with
        | Error (ad,x) -> failwith x
        | Correct(hst) ->
            match hst with
            | HT_server_hello  ->    
                (match parseServerHello payload with
                | Error (ad,x) -> failwith x
                | Correct (pv,sr,sid,cs,cm,extensions) -> 
                    let read_s = {st.read_s with hs_buffer = buf } in
                    let st = {st with read_s = read_s } in
                    let si  = { si with 
                                init_srand = sr;
                                protocol_version = pv;
                                sessionID = sid;
                                cipher_suite = cs;
                                compression = cm;
                    } in
                    let fsh = { nullFServerHello with 
                                pv = pv;
                                rand = sr;
                                sid = sid;
                                suite = cs;
                                comp = cm;
                                ext = extensions;
                                payload = to_log;
                    } in
                    (st,si,fsh)
                    )
            | _ -> failwith "recvServerHello : message type should be HT_server_hello"
        
        
    (* Send a ServerHello message to the network stream *)
    static member send (st:state, ?osi:SessionInfo, ?ofsh:FServerHello) : state * SessionInfo * FServerHello =
    
        let ns = st.ns in

        let fsh = defaultArg ofsh nullFServerHello in
        let si = defaultArg osi nullFSessionInfo in

        let fsh,si = fillFServerHelloANDSi fsh si in

        let msgb = HandshakeMessages.serverHelloBytes si fsh.rand fsh.ext in
        let len = length msgb in
        let rg : Range.range = (len,len) in

        let id = TLSInfo.id st.write_s.epoch in
        let frag = TLSFragment.fragment id Handshake rg msgb in
        let nst,b = Record.recordPacketOut st.write_s.epoch st.write_s.record fsh.pv rg Handshake frag in
        let wst = {st.write_s with record = nst} in
        let st = {st with write_s = wst} in
   
        let fsh = { fsh with payload = b } in

        match Tcp.write ns b with
        | Error(x) -> failwith x
        | Correct() -> (st,si,fsh)

    end
