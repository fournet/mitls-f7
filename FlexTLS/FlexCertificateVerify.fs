#light "off"

module FlexTLS.FlexCertificateVerify

open Bytes
open Error
open TLSInfo
open TLSConstants
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexHandshake




/// <summary>
/// Module receiving, sending and forwarding TLS Certificate Verify messages.
/// </summary>
type FlexCertificateVerify = 
    class
    
    /// <summary>
    /// Overload : Receive a CertificateVerify message from the network stream and check the log on demand
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="nsc"> Next security context to be updated </param>
    /// <param name="fcreq"> FCertificateRequest previously used in the handshake that contains allowed signature and hash algorithms </param>
    /// <param name="log"> Optional log that will be verified if provided </param>
    /// <param name="ms"> Optional master secret that has to be provided to check the log if protocol version is SSL3 </param>
    /// <returns> Updated state * Certificate Verify message </returns>
    static member receive (st:state, nsc:nextSecurityContext, fcreq:FCertificateRequest, ?log:bytes, ?ms:bytes) : state * FCertificateVerify =
        let ms = defaultArg ms empty_bytes in
        let log = defaultArg log empty_bytes in 
        FlexCertificateVerify.receive(st,nsc,fcreq.sigAlgs,log,ms)

    /// <summary>
    /// Overload : Receive a CertificateVerify message from the network stream and check the log on demand
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="nsc"> Next security context to be updated </param>
    /// <param name="algs"> Signature and hash algorithms allowed and usually provided by a Certificate Request </param>
    /// <param name="log"> Optional log that will be verified if provided </param>
    /// <param name="ms"> Optional master secret that has to be provided to check the log if protocol version is SSL3 </param>
    /// <returns> Updated state * Certificate Verify message </returns>
    static member receive (st:state, nsc:nextSecurityContext, algs:list<Sig.alg>, ?log:bytes, ?ms:bytes) : state * FCertificateVerify =
        let ms = defaultArg ms empty_bytes in
        let log = defaultArg log empty_bytes in 
        FlexCertificateVerify.receive(st,nsc.si,algs,log,ms)

    /// <summary>
    /// Receive a CertificateVerify message from the network stream and check the log on demand
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="si"> Session info being negociated in the next security context </param>
    /// <param name="algs"> Signature and hash algorithms allowed and usually provided by a Certificate Request </param>
    /// <param name="log"> Optional log that will be verified if provided </param>
    /// <param name="ms"> Optional master secret that has to be provided to check the log if protocol version is SSL3 </param>
    /// <returns> Updated state * Certificate Verify message </returns>
    static member receive (st:state, si:SessionInfo, algs:list<Sig.alg>, ?log:bytes, ?ms:bytes) : state * FCertificateVerify =
        let ms = defaultArg ms empty_bytes in
        let log = defaultArg log empty_bytes in 
        let checkLog = 
            if not (log = empty_bytes) then true else false
        in
            
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_certificate_verify -> 
            let alg,signature =    
                match parseDigitallySigned algs payload si.protocol_version with
                | Correct(alg,signature) ->
                    if checkLog then
                        (match si.protocol_version with
                        | TLS_1p3 ->
                            (match Cert.get_chain_public_signing_key si.serverID alg with
                            | Error(ad,x) -> failwith x
                            | Correct(vkey) ->
                                if Sig.verify alg vkey log signature then
                                    (alg,signature)
                                else
                                    failwith (perror __SOURCE_FILE__ __LINE__ "Signature does not match !"))
                        | TLS_1p2 | TLS_1p1 | TLS_1p0 ->
                            (match Cert.get_chain_public_signing_key si.clientID alg with
                            | Error(ad,x) -> failwith x
                            | Correct(vkey) ->
                                if Sig.verify alg vkey log signature then
                                    (alg,signature)
                                else
                                    failwith (perror __SOURCE_FILE__ __LINE__ "Signature does not match !"))
                        | SSL_3p0 -> 
                            let ms = 
                                if ms = empty_bytes then 
                                    failwith (perror __SOURCE_FILE__ __LINE__ "Master Secret cannot be empty")
                                else
                                    PRF.coerce (msi si) ms
                            in
                            let (sigAlg,_) = alg in
                            let alg = (sigAlg,NULL) in
                            let expected = PRF.ssl_certificate_verify si ms sigAlg log in
                            (match Cert.get_chain_public_signing_key si.clientID alg with
                            | Error(ad,x) -> failwith x
                            | Correct(vkey) ->
                                if Sig.verify alg vkey expected signature then
                                    (alg,signature)
                                else
                                    failwith (perror __SOURCE_FILE__ __LINE__ "Signature does not match !"))
                        )
                    else
                        (alg,signature)
                | Error(ad,x) -> failwith x
            in
            let fcver : FCertificateVerify = { sigAlg = alg;
                                               signature = signature;
                                               payload = to_log;
                                             } 
            in
            st,fcver
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Unexpected message received: %A" hstype))

    /// <summary>
    /// Prepare a CertificateVerify message that will not be sent to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="log"> Log of the current handshake </param>
    /// <param name="cs"> Ciphersuite of the current Handshake </param>
    /// <param name="pv"> Protocol version of the current Handshake </param>
    /// <param name="alg"> Signature algorithm allowed and usually provided by a Certificate Request </param>
    /// <param name="skey"> Signature secret key associated to the algorithm </param>
    /// <param name="ms"> Optional master secret that has to be provided to compute the log if protocol version is SSL3 </param>
    /// <returns> Certificate Verify bytes * Updated state * Certificate Verify message </returns>
    static member prepare (st:state, log:bytes, cs:cipherSuite, pv:ProtocolVersion, alg:Sig.alg, skey:Sig.skey, ?ms:bytes) : bytes * state * FCertificateVerify =
        let si = { FlexConstants.nullSessionInfo with 
            cipher_suite = cs;
            protocol_version = pv 
        } in
        let ms = defaultArg ms empty_bytes in
        let ams = (PRF.coerce (msi si) ms) in
        let payload,tag = HandshakeMessages.makeCertificateVerifyBytes si ams alg skey log in
        let fcver = { sigAlg = alg; signature = tag; payload = payload } in
        payload,st,fcver 

    /// <summary>
    /// Overload : Send a CertificateVerify (signature over the current log) message to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="log"> Log of the current handshake </param>
    /// <param name="si"> Session info being negociated in the next security context </param>
    /// <param name="alg"> Signature algorithm allowed and usually provided by a Certificate Request </param>
    /// <param name="skey"> Signature secret key associated to the algorithm </param>
    /// <param name="ms"> Optional master secret that has to be provided to compute the log if protocol version is SSL3 </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * Certificate Verify message </returns>
    static member send (st:state, log:bytes, si:SessionInfo, alg:Sig.alg, skey:Sig.skey, ?ms:bytes, ?fp:fragmentationPolicy) : state * FCertificateVerify =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let ms = defaultArg ms empty_bytes in
        FlexCertificateVerify.send(st,log,si.cipher_suite,si.protocol_version,alg,skey,ms,fp)

    /// <summary>
    /// Send a CertificateVerify (signature over the current log) message to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="log"> Log of the current handshake </param>
    /// <param name="cs"> Ciphersuite of the current Handshake </param>
    /// <param name="pv"> Protocol version of the current Handshake </param>
    /// <param name="alg"> Signature algorithm allowed and usually provided by a Certificate Request </param>
    /// <param name="skey"> Signature secret key associated to the algorithm </param>
    /// <param name="ms"> Optional master secret that has to be provided to compute the log if protocol version is SSL3 </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * Certificate Verify message </returns>
    static member send (st:state, log:bytes, cs:cipherSuite, pv:ProtocolVersion, alg:Sig.alg, skey:Sig.skey, ?ms:bytes, ?fp:fragmentationPolicy) : state * FCertificateVerify =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let si = { FlexConstants.nullSessionInfo with 
            cipher_suite = cs;
            protocol_version = pv 
        } in
        let ms = defaultArg ms empty_bytes in
        let ams = (PRF.coerce (msi si) ms) in
        let payload,tag = HandshakeMessages.makeCertificateVerifyBytes si ams alg skey log in
        let st = FlexHandshake.send (st,payload,fp) in
        let fcver = { sigAlg = alg; signature = tag; payload = payload } in
        st,fcver 

    end
