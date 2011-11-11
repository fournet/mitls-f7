module ENC

open Data
open TLSInfo
open Error_handling
open TLSPlain

type symKey
(* Only to be used by PRFs module, when generating keys from keyblob *)
val bytes_to_key: bytes -> symKey
type iv = bytes
type ivOpt =
    | SomeIV of iv
    | NoneIV of unit
type cipher = bytes

val ENC: KeyInfo -> symKey -> ivOpt -> int -> plain -> (ivOpt * cipher) Result
val DEC: KeyInfo -> symKey -> ivOpt -> int -> cipher -> (ivOpt * plain) Result
