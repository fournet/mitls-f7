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
      compression = NullCompression;
      init_crand = [||]
      init_srand = [||]
      }

let isNullSessionInfo s =
  s.clientID = None && s.serverID = None && s.sessionID = None &&
  isNullCipherSuite s.cipher_suite && s.compression = NullCompression &&
  s.init_crand = [||] && s.init_srand = [||]

type KeyInfo = {
    sinfo: SessionInfo
    dir: Direction
    crand: bytes
    srand: bytes
    }

let null_KeyInfo dir minPV =
  let si = null_sessionInfo minPV in
    {sinfo = si;
     dir = dir;
     crand = [||];
     srand = [||];
    }

let dual_KeyInfo ki = 
  let d = dualDirection(ki.dir) in
  {ki with dir = d}
