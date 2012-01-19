module TLSFragment

open Bytes
open TLSInfo
open Formats

// Plain type for AEAD
type fragment =
    | FHandshake of Handshake.fragment
    | FCCS of Handshake.ccsFragment
    | FAlert of Alert.fragment
    | FAppData of AppDataPlain.fragment
val repr: KeyInfo -> int -> fragment -> bytes
val fragment: KeyInfo -> bytes -> ContentType -> ((int * fragment) * bytes)