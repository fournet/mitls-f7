module ENC

open Bytes
open TLSInfo
open Error
open TLSPlain

type symKey
(* Only to be used by PRFs module, when generating keys from keyblob *)
val bytes_to_key: bytes -> symKey
type iv = bytes
type iv3 =
    | SomeIV of iv
    | NoIV of unit
type cipher = bytes

val ENC: KeyInfo -> symKey -> iv3 -> (*int ->*) plain -> (iv3 * cipher)
val DEC: KeyInfo -> symKey -> iv3 -> (*int ->*) cipher -> (iv3 * plain)
