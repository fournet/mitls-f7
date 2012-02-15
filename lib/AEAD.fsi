module AEAD

open Bytes
open Error
open TLSInfo
open TLSKey

val encrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> DataStream.range -> AEADPlain.addData -> AEADPlain.plain -> (ENCKey.iv3 * ENC.cipher)
val decrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> DataStream.range -> 
  AEADPlain.addData -> ENC.cipher -> (ENCKey.iv3 * AEADPlain.plain) Result
