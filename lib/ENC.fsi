module ENC

open Bytes
open TLSInfo
open Error

type cipher = bytes

val ENC: KeyInfo -> ENCKey.key -> ENCKey.iv3 -> int -> AEPlain.plain -> (ENCKey.iv3 * cipher)
val DEC: KeyInfo -> ENCKey.key -> ENCKey.iv3 -> cipher -> (ENCKey.iv3 * AEPlain.plain)
