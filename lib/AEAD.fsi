module AEAD

open Bytes
open Error
open TLSInfo
open TLSKey

val encrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> int -> TLSFragment.addData -> TLSFragment.AEADFragment -> (ENCKey.iv3 * ENC.cipher)
val decrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> int -> TLSFragment.addData -> ENC.cipher -> (ENCKey.iv3 * TLSFragment.AEADFragment) Result