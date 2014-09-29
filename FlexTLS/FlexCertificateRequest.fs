#light "off"

module FlexCertificateRequest

open Bytes
open Error
open TLSInfo
open TLSConstants
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexHandshake




type FlexCertificateRequest =
    class

    /// <summary>
    /// Receive a CertificateRequest message from the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="nsc"> Optional Next security context object updated with new data </param>
    /// <returns> Updated state * next security context * FCertificateRequest message record </returns>
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
                let certReq : FCertificateRequest = {
                    certTypes = certTypes;
                    sigAlgs = sigAlgs;
                    names = names;
                    payload = to_log
                } in
                let si  = { si with client_auth = true} in
                let nsc = { nsc with si = si } in
                    (st,nsc,certReq)
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "message type should be HT_certificate_request")

    /// <summary>
    /// Prepare a CertificateRequest message that won't be sent to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="cs"> Ciphersuite used to generate the request </param>
    /// <param name="pv"> Protocol version used to generate the request </param>
    /// <returns> Payload of the message as bytes * Updated state * FCertificateRequest message record</returns>
    static member prepare (st:state, cs:cipherSuite, pv:ProtocolVersion): bytes * state * FCertificateRequest =
        let payload = HandshakeMessages.certificateRequestBytes true cs pv in
        let fcreq = { FlexConstants.nullFCertificateRequest with sigAlgs = FlexConstants.sigAlgs_ALL ; payload = payload } in
        payload,st,fcreq

    /// <summary>
    /// Send a CertificateRequest message to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="nsc"> Optional next security context to be updated </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * FCertificateRequest message record </returns>
    static member send (st:state, ?nsc:nextSecurityContext, ?fp:fragmentationPolicy): state * FCertificateRequest =
        (* TODO: due to some limitations in miTLS in handling CertificateRequests
           sending this message is currently not as flexible as it could be
           (e.g. we cannot select certification authority names)
           We have to improve miTLS, or write our code in this module.
           Using limited miTLS capabilities for now. *)
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        FlexCertificateRequest.send(st,nsc.si.cipher_suite,nsc.si.protocol_version,fp)

    /// <summary>
    /// Send a CertificateRequest message to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="cs"> Ciphersuite used to generate the request </param>
    /// <param name="pv"> Protocol version used to generate the request </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * FCertificateRequest message record </returns>
    static member send (st:state, cs:cipherSuite, pv:ProtocolVersion, ?fp:fragmentationPolicy): state * FCertificateRequest =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let payload = HandshakeMessages.certificateRequestBytes true cs pv in
        let st = FlexHandshake.send (st,payload,fp) in
        //BB FIXME : miTLS doesn't allow to get back the list of signature algorithms infered from ciphersuite and pv
        // We return dummy values in the FCertificateRequest sigAlgs so it can be used later by FCertificateVerify functions
        let fcreq = { FlexConstants.nullFCertificateRequest with sigAlgs = FlexConstants.sigAlgs_ALL ; payload = payload } in
        st,fcreq
    end
