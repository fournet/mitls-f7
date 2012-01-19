module AEAD

open Bytes
open Error
open TLSInfo
open TLSFragment
open TLSKey

val encrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> int -> MACPlain.addData -> fragment -> (ENCKey.iv3 * ENC.cipher)
val decrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> int -> MACPlain.addData -> ENC.cipher -> (ENCKey.iv3 * fragment) Result