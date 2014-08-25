#light "off"

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
val verify: id -> MAC.key -> LHAEPlain.adata -> range -> plain -> Result<LHAEPlain.plain>
#if ideal
val widen: id -> LHAEPlain.adata -> range -> plain -> plain
#endif
