module TLSFragment

open TLSInfo
open Formats

type fragment

val repr: KeyInfo -> int -> fragment -> Bytes.bytes
val fragment: KeyInfo -> Bytes.bytes -> ContentType -> ((int * fragment) * Bytes.bytes)