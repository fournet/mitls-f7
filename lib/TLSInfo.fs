module TLSInfo

open Bytes
open Principal
open CipherSuites

type sessionID = bytes

type preDirection =
  | CtoS
  | StoC
type Direction = preDirection

let dualDirection dir =
    match dir with
    | CtoS -> StoC
    | StoC -> CtoS

type SessionInfo = {
    clientID: cert option
    serverID: cert option
    sessionID: sessionID option
    protocol_version: ProtocolVersion
    cipher_suite: cipherSuite
    compression: Compression
    init_crand: bytes
    init_srand: bytes
    }

let null_sessionInfo minPV =
    { clientID = None;
      serverID = None;
      sessionID = None;
      protocol_version = minPV;
      cipher_suite = nullCipherSuite;
      compression = Null;
      init_crand = [||]
      init_srand = [||]
      }

type KeyInfo = {
    sinfo: SessionInfo
    dir: Direction
    crand: bytes
    srand: bytes
    }

let null_KeyInfo dir minPV =
    {sinfo = null_sessionInfo minPV;
     dir = dir;
     crand = [||];
     srand = [||];
    }