﻿module AppCommon

open Formats
open CipherSuites
open Principal
open TLSInfo

type helloReqPolicy =
    | HRPIgnore
    | HRPFull
    | HRPResume

type TimeSpan = System.TimeSpan

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
    isGoodSession: SessionInfo -> bool

    (* Sessions database *)
    sessionDBFileName: string
    sessionDBExpiry: TimeSpan
    }

val defaultProtocolOptions: protocolOptions