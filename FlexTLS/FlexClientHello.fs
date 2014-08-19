#light "off"

module FlexClientHello

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


type FlexClientHello =
    class

    (* Receive a ClientHello message from the network stream *)
    static member receive (st:state) : state * SessionInfo * FClientHello =
    
        let buf = st.read_s.buffer in
        let st,hstypeb,len,payload,to_log,rem = FlexFragment.getHSMessage st buf in
    
        match parseHt hstypeb with
        | Error (ad,x) -> failwith x
        | Correct(hst) ->
            match hst with
            | HT_client_hello  ->    
                (match parseClientHello payload with
                | Error (ad,x) -> failwith x
                | Correct (pv,cr,sid,clientCipherSuites,cm,extensions) -> 
                    let si  = { nullFSessionInfo with 
                                init_crand = cr 
                              } in
                    let fch = { nullFClientHello with
                                pv = pv;
                                rand = cr;
                                sid = sid;
                                suites = clientCipherSuites;
                                comps = cm;
                                ext = extensions;
                                payload = to_log;
                              } in
                    (st,si,fch)
                    )
            | _ -> failwith "recvClientHello : Message type should be HT_client_hello"
 

    (* Send a ClientHello message to the network stream *)
    static member send (st:state) (cfg:config) : state * SessionInfo * FClientHello =

        let ns = st.ns in
        let sid = empty_bytes in
        let cr = Nonce.mkHelloRandom() in
        let ci = initConnection Client cr in
        let extL = prepareClientExtensions cfg ci empty_bytes None in
        let ext = clientExtensionsBytes extL in
    
        let b = HandshakeMessages.clientHelloBytes cfg cr sid ext in
        let len = length b in
        let rg : Range.range = (len,len) in

        let id = TLSInfo.id st.write_s.epoch in
        let frag_out = TLSFragment.fragment id Handshake rg b in
        let (nst, b) = Record.recordPacketOut st.write_s.epoch st.write_s.record cfg.maxVer rg Handshake frag_out in
        let wst = {st.write_s with record = nst} in
        let st = {st with write_s = wst} in

        let si  = { nullFSessionInfo with 
                    init_crand = cr
        } in

        let fch = { nullFClientHello with 
                    pv = cfg.maxVer;
                    rand = cr;
                    sid = sid;
                    suites = cfg.ciphersuites;
                    comps = cfg.compressions;
                    ext = ext;
                    payload = b;
        } in
        match Tcp.write ns b with
        | Error(x) -> failwith x
        | Correct() -> (st,si,fch)
    
    end
