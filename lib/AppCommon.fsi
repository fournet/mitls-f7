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

val defaultProtocolOptions: protocolOptions

val max_TLSPlaintext_fragment_length: int
val fragmentLength: int