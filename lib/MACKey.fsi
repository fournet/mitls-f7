module MACKey

open Bytes
open TLSInfo

type key

val GEN: KeyInfo -> key
val LEAK:   KeyInfo -> key -> bytes
val COERCE: KeyInfo -> bytes -> key

val reIndex: KeyInfo -> KeyInfo -> key -> key