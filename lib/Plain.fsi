module Plain

open Bytes
open TLSInfo
open Formats

type plain
val plain: KeyInfo -> bytes -> plain
val repr: KeyInfo -> int -> plain -> bytes

val prepare: KeyInfo -> int -> TLSFragment.addData -> TLSFragment.AEADPlain -> MACPlain.MACed -> plain
val parse: KeyInfo -> int -> TLSFragment.addData -> plain -> (bool * (TLSFragment.AEADPlain * MACPlain.MACed))
