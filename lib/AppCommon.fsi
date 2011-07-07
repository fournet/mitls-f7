module AppCommon

open Formats
open HS_ciphersuites

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

    (* Sessions database *)
    sessionDBFileName: string
    sessionDBExpiry: System.TimeSpan
    }

val defaultProtocolOptions: protocolOptions

val max_TLSPlaintext_fragment_length: int
val fragmentLength: int