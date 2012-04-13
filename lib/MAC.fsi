module MAC

open Bytes
open Algorithms
open TLSInfo

type text = bytes
type tag = bytes

type key

val Mac:    KeyInfo -> key -> text -> tag
val Verify: KeyInfo -> key -> text -> tag -> bool

val GEN: KeyInfo -> key
val LEAK:   KeyInfo -> key -> bytes
val COERCE: KeyInfo -> bytes -> key
