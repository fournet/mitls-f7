module MAC

open Bytes
open Algorithms
open TLSInfo

type text = bytes
type mac = bytes

type key

val MAC:    KeyInfo -> key -> text -> mac
val VERIFY: KeyInfo -> key -> text -> mac -> bool

val GEN: KeyInfo -> key
val LEAK:   KeyInfo -> key -> bytes
val COERCE: KeyInfo -> bytes -> key

val reIndex: KeyInfo -> KeyInfo -> key -> key