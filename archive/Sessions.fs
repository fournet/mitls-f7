module Sessions

open Bytearray
open Data
open Formats
open HS_ciphersuites
open Principal

type sessionID = bytes

type SessionMoreInfo = {
    mi_protocol_version: ProtocolVersionType
    mi_cipher_suite: cipherSuite
    mi_compression: Compression
    mi_ms: bytes
    }

type SessionInfo = {
    role: role;
    clientID: pri_cert option;
    serverID: pri_cert option;
    sessionID: sessionID option
    more_info: SessionMoreInfo
    }

let init_sessionInfo role =
    { role = role;
      clientID = None;
      serverID = None;
      sessionID = None;
      more_info =
        {
        mi_protocol_version = ProtocolVersionType.UnknownPV;
        mi_cipher_suite = nullCipherSuite;
        mi_compression = Null;
        mi_ms = empty_bstr
        }
      }