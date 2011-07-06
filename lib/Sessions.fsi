module Sessions

open Bytearray
open Data
open Formats
open HS_ciphersuites

type prerole =
    | ClientRole
    | ServerRole

type role = prerole

type sessionID = bytes

type SessionMoreInfo = {
    mi_cipher_suite: CipherSuite
    mi_compression: Compression
    mi_pms: bytes 
    }

type SessionInfo = {
    role: role;
    clientID: string option;
    serverID: string option;
    sessionID: sessionID option
    more_info: SessionMoreInfo
    }

val init_sessionInfo: role -> SessionInfo
