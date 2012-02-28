module TLSInfo

open Bytes
open Certificate
open CipherSuites

type sessionID = bytes

type preDirection =
    | CtoS
    | StoC
type Direction = preDirection

type preRole =
    | Client
    | Server
type Role = preRole

//val dualDirection: Direction -> Direction

(* SessionInfo and KeyInfo: Session and Connection level public immutable data.
   Used for indexing *)

type SessionInfo = {
    clientID: cert option;
    serverID: cert option;
    sessionID: sessionID option;
    (* prev_sid: sessionID option; Pointer to the previous session over the same connection *)
    protocol_version: ProtocolVersion;
    cipher_suite: cipherSuite;
    compression: Compression;
    init_crand: bytes;
    init_srand: bytes
    }

type KeyInfo = {
    sinfo: SessionInfo;
    dir: Direction;
    crand: bytes;
    srand: bytes;
    (* cVerifyData: bytes
    sVerifyData: bytes *)
    }

type ConnectionInfo =
    { id_in:  KeyInfo;
      id_out: KeyInfo}

val null_sessionInfo: ProtocolVersion -> SessionInfo
val isNullSessionInfo: SessionInfo -> bool
val null_KeyInfo: Direction -> ProtocolVersion -> KeyInfo
val dual_KeyInfo: KeyInfo -> KeyInfo

// Application configuration options
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

    (* Sessions database *)
    sessionDBFileName: string
    sessionDBExpiry: TimeSpan
    }

val defaultProtocolOptions: protocolOptions