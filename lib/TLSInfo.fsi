module TLSInfo

open Data
open Principal
open HS_ciphersuites

type prerole
type role = prerole
type sessionID = bytes

type SessionInfo = {
    role: role
    clientID: pri_cert option
    serverID: pri_cert option
    sessionID: sessionID option
    protocol_version: ProtocolVersionType
    cipher_suite: cipherSuite
    compression: Compression
    init_crand: bytes
    init_srand: bytes
    }

type KeyInfo = {
    sinfo: SessionInfo
    crand: bytes
    srand: bytes
 (* cVerifyData: bytes
    sVerifyData: bytes *)
    }