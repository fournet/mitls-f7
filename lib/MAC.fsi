module MAC

open Bytes
open Error
open TLSInfo

type macKey
(* Only to be used by PRFs module, when generating keys from keyblob *)
val bytes_to_key: bytes -> macKey
type mac_plain = bytes
type mac = bytes

val MAC: KeyInfo -> macKey -> mac_plain -> mac Result
val VERIFY: KeyInfo -> macKey -> mac_plain -> mac -> unit Result
