#light "off"

module FlexCertificateVerify

open Bytes
open TLSInfo
open TLSConstants

open FlexTypes
open FlexConstants




type FlexCertificateVerify = 
    class
    
    static member receive (st:state) : state * FCertificateVerify =
        st,nullFCertificateVerify


    static member send (st:state, log:bytes, pv:ProtocolVersion, alg:Sig.alg, skey:Sig.skey, ?ms:PRF.masterSecret) : state * FCertificateVerify =
        let si = { nullSessionInfo with protocol_version = pv } in
        let ms = defaultArg ms (PRF.coerce (msi si) empty_bytes) in
        let payload,_ = HandshakeMessages.makeCertificateVerifyBytes si ms alg skey log in
        let fcver = { nullFCertificateVerify with payload = payload } in
        st,fcver 

    end
