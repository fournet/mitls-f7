module Plain

open Bytes
open TLSInfo

type plain
val plain: KeyInfo -> bytes -> plain
val repr: KeyInfo -> plain -> bytes

val prepare: KeyInfo -> int -> TLSFragment.fragment -> MACPlain.MACed -> plain
val parse: KeyInfo -> int -> plain -> (bool * (TLSFragment.fragment * MACPlain.MACed))