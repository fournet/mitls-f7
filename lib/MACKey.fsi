module MACKey

open Bytes
open TLSInfo

val keysize: KeyInfo -> int 
type key

val GEN: KeyInfo -> key
val LEAK:   KeyInfo -> key -> bytes
val COERCE: KeyInfo -> bytes -> key