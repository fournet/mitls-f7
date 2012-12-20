module MAC

open Bytes
open TLSConstants
open TLSInfo

type text = bytes
type tag = bytes

type key

val Mac:    epoch -> key -> text -> tag
val Verify: epoch -> key -> text -> tag -> bool

val GEN: epoch -> key
val LEAK:   epoch -> key -> bytes
val COERCE: epoch -> bytes -> key
