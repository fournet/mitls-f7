module LHAEPlain
open Bytes
open TLSInfo
open Range

type adata = bytes
type fragment
type plain = fragment

val plain: epoch -> adata -> range -> bytes -> plain
val repr:  epoch -> adata -> range -> plain -> bytes

val makeAD: epoch -> StatefulPlain.history -> StatefulPlain.adata -> adata
val parseAD: epoch -> adata -> StatefulPlain.adata
val StatefulPlainToLHAEPlain: epoch -> StatefulPlain.history -> StatefulPlain.adata -> adata -> range -> StatefulPlain.plain -> plain
val LHAEPlainToStatefulPlain: epoch -> StatefulPlain.history -> StatefulPlain.adata -> adata -> range -> plain -> StatefulPlain.plain

#if ideal
val widen: epoch -> adata -> range -> fragment -> fragment
#endif