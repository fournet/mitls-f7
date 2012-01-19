module AEAD

open Bytes
open Error
open TLSInfo
open TLSKey

val encrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> int -> MACPlain.addData -> TLSFragment.fragment -> (ENCKey.iv3 * ENC.cipher)
val decrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> int -> MACPlain.addData -> ENC.cipher -> (ENCKey.iv3 * TLSFragment.fragment) Result