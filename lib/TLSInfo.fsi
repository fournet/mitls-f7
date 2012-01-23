module TLSInfo

open Bytes
open Principal
open CipherSuites

type sessionID = bytes

type preDirection =
    | CtoS
    | StoC
type Direction = preDirection

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

val null_sessionInfo: ProtocolVersion -> SessionInfo
val null_KeyInfo: Direction -> ProtocolVersion -> KeyInfo
val dual_KeyInfo: KeyInfo -> KeyInfo