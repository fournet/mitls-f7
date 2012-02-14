module Plain

open Bytes
open TLSInfo
open Formats

type plain
val plain: KeyInfo -> DataStream.range -> bytes -> plain
val repr: KeyInfo -> DataStream.range -> plain -> bytes

val prepare: KeyInfo -> DataStream.range -> TLSFragment.addData -> TLSFragment.AEADPlain -> MACPlain.MACed -> plain
val parse: KeyInfo -> DataStream.range -> TLSFragment.addData -> plain -> (bool * (TLSFragment.AEADPlain * MACPlain.MACed))
