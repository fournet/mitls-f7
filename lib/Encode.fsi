module Encode

open Bytes
open Error
open TLSInfo
open TLSConstants
open Range

#if verify
type preds = | CipherRange of epoch * range * nat
#endif

type plain
val plain: epoch -> nat -> bytes -> plain
val repr:  epoch -> nat -> plain -> bytes

type parsed
type tag

val mac: epoch -> MAC.key -> LHAEPlain.adata -> range -> LHAEPlain.plain -> tag
val verify: epoch -> MAC.key -> LHAEPlain.adata -> range -> parsed -> LHAEPlain.plain Result

val encode: epoch -> nat -> range -> LHAEPlain.adata -> LHAEPlain.plain -> tag -> plain
val encodeNoPad: epoch -> nat -> range -> LHAEPlain.adata -> LHAEPlain.plain -> tag -> plain

val decode: epoch -> LHAEPlain.adata -> range -> nat -> plain -> parsed
val decodeNoPad: epoch -> LHAEPlain.adata -> range -> nat -> plain -> parsed
