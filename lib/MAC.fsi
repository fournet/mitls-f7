module MAC

open Bytes
open TLSInfo

type macKey
(* Only to be used by PRFs module, when generating keys from keyblob *)
val bytes_to_key: bytes -> macKey
type mac_plain = bytes
type mac = bytes

val MAC: KeyInfo -> macKey -> mac_plain -> mac
val VERIFY: KeyInfo -> macKey -> mac_plain -> mac -> bool
