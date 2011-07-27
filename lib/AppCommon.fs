module AppCommon

open Formats
open HS_ciphersuites
open Principal

type helloReqPolicy =
    | HRPIgnore
    | HRPFull
    | HRPResume

type protocolOptions = {
    minVer: ProtocolVersionType
    maxVer: ProtocolVersionType
    ciphersuites: cipherSuites
    compressions: Compression list

    (* Handshake specific options *)
    honourHelloReq: helloReqPolicy
    allowAnonCipherSuite: bool
    certificateValidationPolicy: pri_cert list -> bool
    safe_renegotiation: bool
    
    (* Sessions database *)
    sessionDBFileName: string
    sessionDBExpiry: System.TimeSpan
    }

let defaultCertificateValidationPolicy certList = true

let defaultProtocolOptions ={
    minVer = ProtocolVersionType.SSL_3p0
    maxVer = ProtocolVersionType.TLS_1p2
    ciphersuites = [ TLS_RSA_WITH_AES_128_CBC_SHA;
                    TLS_RSA_WITH_RC4_128_MD5;
                    TLS_RSA_WITH_RC4_128_SHA;       
                    TLS_RSA_WITH_DES_CBC_SHA;
                    TLS_NULL_WITH_NULL_NULL;
                    TLS_RSA_WITH_NULL_MD5;               
                    TLS_RSA_WITH_NULL_SHA;
                  ]
    compressions = [ Null ]

    honourHelloReq = HRPResume
    allowAnonCipherSuite = false
    certificateValidationPolicy = defaultCertificateValidationPolicy
    safe_renegotiation = true

    sessionDBFileName = "sessionDBFile.bin"
    sessionDBExpiry = new System.TimeSpan(2,0,0,0) (* two days *)
    }

let max_TLSPlaintext_fragment_length = 1<<<14 (* just a reminder *)
let fragmentLength = max_TLSPlaintext_fragment_length (* 1 *)