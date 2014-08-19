#light "off"

module FlexCertificateRequest

open Tcp
open Bytes
open Error
open TLSInfo
open TLSConstants
open HandshakeMessages

open FlexTypes
open FlexFragment

(* TODO : Complete FCertificateRequest type and nullFCertificateRequest constructor before continuing *)

(*
(* Receive a CertificateRequest message from the network stream *)
let recvCertificateRequest (st:state) (si:SessionInfo) : state * SessionInfo * FCertificateRequest =
    
    let buf = st.read_s.buffer in
    let st,hstypeb,len,payload,to_log,rem = getHSMessage st buf in
    
    match parseHt hstypeb with
    | Error (ad,x) -> failwith x
    | Correct(hst) ->
        match hst with
        | HT_certificate_request  ->  
            (match HandshakeMessages.parseCertificateRequest pv payload with
            | Error (ad,x) -> failwith x
            | Correct (certC) -> 
                let cert = { nullFCertificateRequest with sign = certC; } in
                match role with
                | Client ->
                    let si  = { si with 
                                client_auth = true;
                                clientID = certC;
                    } in
                    (st,si,cert)
                | Server ->
                    let si  = { si with 
                                serverID = certC;
                    } in
                    (st,si,cert)
                    )
        | _ -> failwith "recvCertificateRequest : message type should be HT_certificate_request"



(* Send a CertificateRequest message to the network stream *)
let sendCertificateRequest (st:state) (si:SessionInfo) (fcr:FCertificateRequest): state * SessionInfo * FCertificateRequest =
    
    let ns = st.ns in
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

    match Tcp.write ns b with
    | Error(x) -> failwith x
    | Correct() -> (st,si,fcr)
*)