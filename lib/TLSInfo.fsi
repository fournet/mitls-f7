module TLSInfo

open Data
open Principal
open CipherSuites

type sessionID = bytes

type preDirection =
    | CtoS
    | StoC

type Direction = preDirection

val dualDirection: Direction -> Direction

type SessionInfo = {
    clientID: cert option;
    serverID: cert option;
    sessionID: sessionID option;
    (* prev_sid: sessionID option; Pointer to the previous session over the same connection *)
    protocol_version: ProtocolVersionType;
    cipher_suite: cipherSuite;
    compression: Compression;
    init_crand: bytes;
    init_srand: bytes
    }

val init_sessionInfo: SessionInfo

type KeyInfo = {
    sinfo: SessionInfo;
    dir: Direction;
    crand: bytes;
    srand: bytes;
    (* cVerifyData: bytes
    sVerifyData: bytes *)
    }

val init_KeyInfo: SessionInfo -> Direction -> KeyInfo
