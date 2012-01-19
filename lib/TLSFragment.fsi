module TLSFragment

open Bytes
open TLSInfo
open Formats

// Plain type for AEAD
type fragment
val repr: KeyInfo -> int -> fragment -> bytes
val fragment: KeyInfo -> bytes -> ContentType -> ((int * fragment) * bytes)