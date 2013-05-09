module MAC

open Bytes
open TLSConstants
open TLSInfo

type text = bytes
type tag = bytes

type key

val Mac:    id -> key -> text -> tag
val Verify: id -> key -> text -> tag -> bool

val GEN: id -> key
val LEAK:   id -> key -> bytes
val COERCE: id -> bytes -> key
