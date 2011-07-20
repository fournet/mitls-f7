module Sessions

open Bytearray
open Data
open Formats
open HS_ciphersuites
open Principal

type prerole =
    | ClientRole
    | ServerRole

type role = prerole

type sessionID = bytes

type SessionMoreInfo = {
    mi_protocol_version: ProtocolVersionType
    mi_cipher_suite: CipherSuite
    mi_compression: Compression
    mi_pms: bytes
    }

type SessionInfo = {
    role: role;
    clientID: pri_cert option;
    serverID: pri_cert option;
    sessionID: sessionID option
    more_info: SessionMoreInfo
    }

val init_sessionInfo: role -> SessionInfo
