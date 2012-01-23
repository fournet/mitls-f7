module Plain

open Bytes
open TLSInfo
open Formats

type plain
val plain: KeyInfo -> bytes -> plain
val repr: KeyInfo -> int -> plain -> bytes

val prepare: KeyInfo -> int -> TLSFragment.addData -> TLSFragment.AEADFragment -> MACPlain.MACed -> plain
val parse: KeyInfo -> int -> TLSFragment.addData -> plain -> (bool * (TLSFragment.AEADFragment * MACPlain.MACed))