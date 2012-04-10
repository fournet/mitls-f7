module FragCommon

open Bytes
open TLSInfo


val cipherLength: SessionInfo -> int -> int
val splitInFrag: KeyInfo -> bytes -> (int * bytes * bytes)

val estimateLengths: SessionInfo -> int -> int list
val getFragment: SessionInfo -> int -> bytes -> bytes*bytes

