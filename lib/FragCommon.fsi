module FragCommon

open Bytes
open TLSInfo

val fragmentLength: int
val cipherLength: SessionInfo -> int -> int
val splitInFrag: KeyInfo -> bytes -> (int * bytes * bytes)

val max_TLSPlaintext_fragment_length: int
val max_TLSCompressed_fragment_length: int
val max_TLSCipher_fragment_length: int

val estimateLengths: SessionInfo -> int -> int list
val getFragment: SessionInfo -> int -> bytes -> bytes*bytes

