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

let init_sessionInfo role =
    { role = role;
      clientID = None;
      serverID = None;
      sessionID = None;
      more_info =
        {
        mi_cipher_suite = TLS_NULL_WITH_NULL_NULL;
        mi_compression = Null;
        mi_pms = empty_bstr;
        }
      }