module AEAD

open Bytes
open Error
open TLSInfo
open TLSKey

val encrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> AEADPlain.data -> DataStream.range -> AEADPlain.plain -> (ENCKey.iv3 * ENC.cipher)
val decrypt: KeyInfo -> AEADKey -> ENCKey.iv3 -> AEADPlain.data -> ENC.cipher -> (ENCKey.iv3 * DataStream.range * AEADPlain.plain) Result
