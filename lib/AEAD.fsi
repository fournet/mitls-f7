module AEAD

open Bytes
open Error
open TLSInfo
open TLSKey

val encrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> DataStream.range -> TLSFragment.addData -> TLSFragment.AEADPlain -> (ENCKey.iv3 * ENC.cipher)
val decrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> DataStream.range -> TLSFragment.addData -> ENC.cipher -> (ENCKey.iv3 * TLSFragment.AEADPlain) Result
