#light "off"

module FlexCertificateRequest

open Tcp
open Bytes
open Error
open TLSInfo
open TLSConstants
open HandshakeMessages

open FlexTypes
open FlexRecord

(* TODO : Complete FCertificateRequest type and nullFCertificateRequest constructor before continuing *)


type FlexCertificateRequest =
    class

    (*
    (* Receive a CertificateRequest message from the network stream *)
    let receive (st:state) (nsc:nextSecurityContext) : state * nextSecurityContext * FCertificateRequest =
    
        let si = nsc.si in
        let buf = st.read_s.buffer in
        let st,hstypeb,len,payload,to_log,buf = FlexRecord.getHSMessage st buf in
    
        match parseHt hstypeb with
        | Error (ad,x) -> failwith x
        | Correct(hst) ->
            match hst with
            | HT_certificate_request  ->  
                (match HandshakeMessages.parseCertificateRequest pv payload with
                | Error (ad,x) -> failwith x
                | Correct (certC) -> 
                    let cert = { nullFCertificateRequest with sign = certC; } in
                    let read_s = {st.read_s with buffer = buf } in
                    let st = {st with read_s = read_s } in
                    match role with
                    | Client ->
                        let si  = { si with 
                                    client_auth = true;
                                    clientID = certC;
                        } in
                        let nsc = { nsc with si = si } in
                        (st,nsc,cert)
                    | Server ->
                        let si  = { si with 
                                    serverID = certC;
                        } in
                        let nsc = { nsc with si = si } in
                        (st,nsc,cert)
                        )
            | _ -> failwith "recvCertificateRequest : message type should be HT_certificate_request"



    (* Send a CertificateRequest message to the network stream *)
    let send (st:state) (nsc:nextSecurityContext) (fcr:FCertificateRequest): state * nextSecurityContext * FCertificateRequest =
    
        let ns = st.ns in
        let si = nsc.si in
        let pv = si.protocol_version in
        let cs = si.cipher_suite in
        let sign = fcr.sign in
        let b = HandshakeMessages.certificateRequestBytes sign cs pv in
        let len = length b in
        let rg : Range.range = (len,len) in

        let id = TLSInfo.id st.write_s.epoch in
        let frag_out = TLSFragment.fragment id Handshake rg b in
        let (nst, b) = Record.recordPacketOut st.write_s.epoch st.write_s.record pv rg Handshake frag_out in
        let wst = {st.write_s with record = nst} in
        let st = {st with write_s = wst} in

        let nsc = { nsc with si = si } in
        match Tcp.write ns b with
        | Error(x) -> failwith x
        | Correct() -> (st,nsc,fcr)
    *)

    end
