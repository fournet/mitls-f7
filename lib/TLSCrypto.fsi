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
type masterSecret = bytes
val prfVerifyData: ProtocolVersionType -> cipherSuite -> masterSecret -> role -> bytes -> bytes Result

(* Used when generating the MS from the PMS *)
type preMasterSecret = bytes
val prfMS: protocolVersionType -> cipherSuite -> 