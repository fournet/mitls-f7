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
val plain: epoch -> LHAEPlain.adata -> nat -> bytes -> plain
val repr:  epoch -> LHAEPlain.adata -> range -> plain -> bytes

val mac: epoch -> MAC.key -> LHAEPlain.adata -> range -> LHAEPlain.plain -> plain
val verify: epoch -> MAC.key -> LHAEPlain.adata -> range -> plain -> LHAEPlain.plain Result
