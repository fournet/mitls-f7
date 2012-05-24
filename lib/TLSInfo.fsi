module TLSInfo

open Bytes
open Algorithms
open Certificate
open CipherSuites

type sessionID = bytes
type preRole =
    | Client
    | Server
type Role = preRole

type SessionInfo = {
    clientID: cert option;
    serverID: cert option;
    sessionID: sessionID option;
    protocol_version: ProtocolVersion;
    cipher_suite: cipherSuite;
    compression: Compression;
    init_crand: bytes;
    init_srand: bytes
    }

type preEpoch
type epoch = preEpoch

val epochSI: epoch -> SessionInfo
val epochSRand: epoch -> bytes
val epochCRand: epoch -> bytes

//type epoch = {
//    sinfo: SessionInfo;
//    dir: Direction;
//    crand: bytes;
//    srand: bytes;
//    (* cVerifyData: bytes
//    sVerifyData: bytes *)
//    }

// Role is of the writer
type ConnectionInfo =
    { role: Role;
      id_in:  epoch;
      id_out: epoch}
val connectionRole: ConnectionInfo -> Role

val null_sessionInfo: ProtocolVersion -> SessionInfo
val isNullSessionInfo: SessionInfo -> bool
val initConnection: Role -> bytes -> ConnectionInfo
val nextConnection: ConnectionInfo -> bytes -> bytes -> SessionInfo -> ConnectionInfo
//val dual_KeyInfo: epoch -> epoch

// Application configuration options
type helloReqPolicy =
    | HRPIgnore
    | HRPFull
    | HRPResume

type config = {
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

    (* Sessions database *)
    sessionDBFileName: string
    sessionDBExpiry: TimeSpan
    }

val defaultConfig: config