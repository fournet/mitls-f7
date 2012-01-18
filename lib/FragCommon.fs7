module FragCommon

open Bytes
open TLSInfo

val fragmentLength: int
val cipherLength: SessionInfo -> int -> int
val splitInFrag: KeyInfo -> bytes -> (int * bytes * bytes)