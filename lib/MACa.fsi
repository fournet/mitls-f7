module MACa

open Bytes
open TLSConstants
open TLSInfo

val a: macAlg
type text = bytes
type tag = bytes

type key

val Mac:    epoch -> key -> text -> tag
val Verify: epoch -> key -> text -> tag -> bool

val GEN: epoch -> key

