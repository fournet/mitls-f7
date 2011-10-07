module TLSCrypto

open Data
open Formats (* for ProtocolVersionType and role *)
open Algorithms
open HS_ciphersuites
open Error_handling

(* TLS-aware MAC function
   - Use standard HMAC for TLS
   - Use custom keyed hash for SSL (implemented internally in this module)
*)

val MAC: ProtocolVersionType -> hashAlg (* or ciphersuite? *) -> bytes -> bytes Result

(* PRF *)

(* Used when generating verifiData for the Finished message *)
val prfVerifyData: ProtocolVersionType -> cipherSuite -> bytes -> role -> bytes -> bytes Result

(* Used when generating the MS from the PMS *)
val prfMS: protocolVersionType -> cipherSuite