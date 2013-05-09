module Encode

open Bytes
open Error
open TLSError
open TLSInfo
open TLSConstants
open Range

#if verify
type preds = | CipherRange of id * range * nat
#endif

type plain
val plain: id -> LHAEPlain.adata -> nat -> bytes -> plain
val repr:  id -> LHAEPlain.adata -> range -> plain -> bytes

val mac: id -> MAC.key -> LHAEPlain.adata -> range -> LHAEPlain.plain -> plain
val verify: id -> MAC.key -> LHAEPlain.adata -> range -> plain -> LHAEPlain.plain Result
