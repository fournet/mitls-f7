#light "off"

module FlexCertificateVerify

open Bytes
open Error
open TLSInfo
open TLSError
open TLSConstants
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexHandshake
open FlexSecrets




type FlexCertificateVerify = 
    class
    
    (* Receive function will take the expected signature algorithms list and cross-check it with the sig alg of the received message or fail *)
    // TODO : The matching with algorithms provided by the CertificateRequest should probably be done outside this function for FlexTLS

    static member receiveANDcheckSignature (st:state, si:SessionInfo, algs:list<Sig.alg>, log:bytes, ?ms:bytes) : state * FCertificateVerify =
        // TODO : This is duplicated from HandshakeMessages.certificateVerifyCheck
        // In this function the failure throw an exception if the signature don't match the certificate
        let ms = defaultArg ms empty_bytes in
        
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        
        let alg,signature =    
            match parseDigitallySigned algs payload si.protocol_version with
            | Correct(alg,signature) ->
                (match si.protocol_version with
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
                            FlexSecrets.ms_to_ams ms si
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
            | Error(ad,x) -> failwith x
        in
        let fcver : FCertificateVerify = { sigAlg = alg;
                                           signature = signature;
                                           payload = to_log;
                                         } 
        in
        st,fcver

    static member receive (st:state, pv:ProtocolVersion, algs:list<Sig.alg>) : state * FCertificateVerify =
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        let alg,signature =
            match hstype with
            | HT_certificate_verify  ->
                // TODO : This is partly duplicated from HandshakeMessages.certificateVerifyCheck
                // We strip it from the signature verification which is automatic in miTLS
                // We could fix miTLS to do this verification at the Handshake level instead and use the new function
                (match parseDigitallySigned algs payload pv with
                | Correct(alg,signature) -> alg,signature
                | Error(ad,x) -> failwith x
                )
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "message type should be HT_certificate_verify")
        in
        let fcver : FCertificateVerify = { sigAlg = alg;
                                           signature = signature;
                                           payload = to_log;
                                         } 
        in
        st,fcver

    (* Send function for the Client to answer with a proper algorithm and by signing the log with it's secret key *)
    static member send (st:state, log:bytes, pv:ProtocolVersion, alg:Sig.alg, skey:Sig.skey, ?ms:PRF.masterSecret) : state * FCertificateVerify =
        let si = { nullSessionInfo with protocol_version = pv } in
        let ms = defaultArg ms (PRF.coerce (msi si) empty_bytes) in
        let payload,_ = HandshakeMessages.makeCertificateVerifyBytes si ms alg skey log in
        let fcver = { nullFCertificateVerify with payload = payload } in
        st,fcver 

    end
