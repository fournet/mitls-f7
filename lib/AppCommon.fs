module AppCommon

open Formats
open CipherSuites
open Principal
open TLSInfo

type helloReqPolicy =
    | HRPIgnore
    | HRPFull
    | HRPResume

type protocolOptions = {
    minVer: ProtocolVersion
    maxVer: ProtocolVersion
    ciphersuites: cipherSuites
    compressions: Compression list

    (* Handshake specific options *)
    (* Client side *)
    honourHelloReq: helloReqPolicy
    allowAnonCipherSuite: bool
    (* Server side *)
    request_client_certificate: bool
    check_client_version_in_pms_for_old_tls: bool
    server_cert_file: string (* FIXME: certificates should be found in a better way. To be fixed *)
    (* Common *)
    certificateValidationPolicy: cert list -> bool
    safe_renegotiation: bool
    isCompatibleSession: SessionInfo -> SessionInfo -> bool
    
    (* Sessions database *)
    sessionDBFileName: string
    sessionDBExpiry: System.TimeSpan
    }

let defaultCertificateValidationPolicy certList = true
// By default, a the new session is compatible only if it's the same as the old session.
// This means that AppData will remain valid with re-keying.
let defaultSessionCompatibility oldSi newSi = (oldSi = newSi)

let defaultProtocolOptions ={
    minVer = SSL_3p0
    maxVer = TLS_1p2
    ciphersuites = cipherSuites_of_nameList
                    [ TLS_RSA_WITH_AES_128_CBC_SHA;
                      TLS_RSA_WITH_3DES_EDE_CBC_SHA;
                    ]
    compressions = [ Null ]

    honourHelloReq = HRPResume
    allowAnonCipherSuite = false
    request_client_certificate = false
    check_client_version_in_pms_for_old_tls = true
    server_cert_file = "server"
    certificateValidationPolicy = defaultCertificateValidationPolicy
    safe_renegotiation = true
    isCompatibleSession = defaultSessionCompatibility

    sessionDBFileName = "sessionDBFile.bin"
    sessionDBExpiry = new System.TimeSpan(2,0,0,0) (* two days *)
    }