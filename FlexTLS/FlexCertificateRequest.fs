#light "off"

module FlexCertificateRequest

open Tcp
open Bytes
open Error
open TLSInfo
open TLSConstants
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexRecord
open FlexHandshake

type FlexCertificateRequest =
    class

    
    (* Receive a CertificateRequest message from the network stream *)
    static member receive (st:state, ?nsc:nextSecurityContext) : state * nextSecurityContext * FCertificateRequest =
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let si = nsc.si in
        let pv = si.protocol_version in
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_certificate_request  ->  
            (match parseCertificateRequest pv payload with
            | Error (_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (certTypes,sigAlgs,names) -> 
                let certReq :FCertificateRequest =
                    {certTypes = certTypes;
                     sigAlgs = sigAlgs;
                     names = names;
                     payload = to_log} in
                let si  = { si with client_auth = true} in
                let nsc = { nsc with si = si } in
                    (st,nsc,certReq)
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "message type should be HT_certificate_request")


    (* Send a CertificateRequest message to the network stream *)
    static member send (st:state, ?nsc:nextSecurityContext, ?fcr:FCertificateRequest, ?fp:fragmentationPolicy): state * FCertificateRequest =
        (* TODO: due to some limitations in miTLS in handling CertificateRequests
           sending this message is currently not as flexible as it could be
           (e.g. we cannot select certification authority names)
           We could either improve miTLS, or write our code in this module.
           Using limited miTLS capabilities for now. *)
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let fcr = defaultArg fcr FlexConstants.nullFCertificateRequest in
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        // FIXME: next function should take fcr fields as input. To be fixed in miTLS or by re-implementing here
        let payload = HandshakeMessages.certificateRequestBytes true nsc.si.cipher_suite nsc.si.protocol_version in
        let st = FlexHandshake.send (st,payload,fp) in
        st,{fcr with payload = payload}
    end
