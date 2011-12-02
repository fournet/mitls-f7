module Mac

open Bytes
open Algorithms
// open TLSInfo

type id = TLSInfo.KeyInfo

val keysize: id -> int 
type keybytes = bytes
type key = {bytes:keybytes}

val tagsize: id -> int
type tag = bytes

type text = bytes

val GEN: id -> key
val MAC:    id -> key -> text -> tag
val VERIFY: id -> key -> text -> tag -> bool
val LEAK:   id -> key -> keybytes
val COERCE: id -> keybytes -> key

