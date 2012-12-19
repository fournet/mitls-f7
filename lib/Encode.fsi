module Encode

open Bytes
open Error
open TLSInfo
open TLSConstants

#if verify
type preds = | CipherRange of epoch * range * nat
#endif

type plain
val plain: epoch -> nat -> bytes -> plain
val repr:  epoch -> nat -> plain -> bytes

type parsed
type tag

val mac: epoch -> MAC.key -> AEADPlain.adata -> range -> AEADPlain.plain -> tag
val verify: epoch -> MAC.key -> AEADPlain.adata -> range -> parsed -> AEADPlain.plain Result

val encode: epoch -> nat -> nat -> range -> AEADPlain.adata -> AEADPlain.plain -> tag -> plain
val encodeNoPad: epoch -> nat -> range -> AEADPlain.adata -> AEADPlain.plain -> tag -> plain

val decode: epoch -> nat -> AEADPlain.adata -> range -> nat -> plain -> parsed
val decodeNoPad: epoch -> AEADPlain.adata -> range -> nat -> plain -> parsed
