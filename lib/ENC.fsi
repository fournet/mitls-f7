module ENC

open Bytes
open TLSInfo
open Error

type cipher = bytes

val ENC: KeyInfo -> ENCKey.key -> ENCKey.iv3 -> DataStream.range -> Plain.plain -> (ENCKey.iv3 * cipher)
val DEC: KeyInfo -> ENCKey.key -> ENCKey.iv3 -> cipher -> (ENCKey.iv3 * Plain.plain)
