module AEAD

open Bytes
open Error
open TLSInfo
open TLSPlain
open TLSKey

val encrypt: KeyInfo -> AEADKey -> ENC.iv3 -> int -> add_data -> fragment -> (ENC.iv3 * ENC.cipher)
val decrypt: KeyInfo -> AEADKey -> ENC.iv3 -> int -> add_data -> ENC.cipher -> (ENC.iv3 * fragment) Result