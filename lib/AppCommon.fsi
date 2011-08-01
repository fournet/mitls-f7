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
    (* Client side *)
    honourHelloReq: helloReqPolicy
    allowAnonCipherSuite: bool
    (* Server side *)
    request_client_certificate: bool
    check_client_version_in_pms_for_old_tls: bool
    server_cert_file: string (* FIXME: certificates should be found in a better way. To be fixed *)
    (* Common *)
    certificateValidationPolicy: pri_cert list -> bool
    safe_renegotiation: bool

    (* Sessions database *)
    sessionDBFileName: string
    sessionDBExpiry: System.TimeSpan
    }

val defaultProtocolOptions: protocolOptions

val max_TLSPlaintext_fragment_length: int
val fragmentLength: int