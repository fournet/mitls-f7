module ENC

open Bytes
open TLSInfo
open Error

type cipher = bytes

val ENC: KeyInfo -> ENCKey.key -> ENCKey.iv3 -> DataStream.range -> AEPlain.plain -> (ENCKey.iv3 * cipher)
val DEC: KeyInfo -> ENCKey.key -> ENCKey.iv3 -> cipher -> (ENCKey.iv3 * AEPlain.plain)
