module Encode

open Bytes
open Error
open TLSInfo
open TLSConstants

type plain
val plain: epoch -> nat -> bytes -> plain
val repr:  epoch -> nat -> plain -> bytes

type MACPlain
type tag
val macPlain: epoch -> range -> AEADPlain.adata -> AEADPlain.plain -> MACPlain
val mac: epoch -> MAC.key -> MACPlain -> tag
val verify: epoch -> MAC.key -> MACPlain -> tag -> bool

val encode: epoch -> range -> AEADPlain.adata -> AEADPlain.plain -> tag -> nat * plain
val encodeNoPad: epoch -> range -> AEADPlain.adata -> AEADPlain.plain -> tag -> nat * plain

val decode: epoch -> AEADPlain.adata -> nat -> plain -> (range * AEADPlain.plain * tag * bool) Result
val decodeNoPad: epoch -> AEADPlain.adata -> nat -> plain -> (range * AEADPlain.plain * tag)
