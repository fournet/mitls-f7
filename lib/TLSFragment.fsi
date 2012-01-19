module TLSFragment

open TLSInfo
open Formats

// Plain type for AEAD
type fragment
val repr: KeyInfo -> int -> fragment -> Bytes.bytes
val fragment: KeyInfo -> Bytes.bytes -> ContentType -> ((int * fragment) * Bytes.bytes)

// Plain type for MAC
type add_data = bytes // public
type macPlain
val macPlain: KeyInfo -> add_data -> fragment -> macPlain