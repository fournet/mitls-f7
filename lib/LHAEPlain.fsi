module LHAEPlain
open Bytes
open TLSInfo
open Range
open TLSError

type adata = bytes
type fragment
type plain = fragment

val plain: id -> adata -> range -> bytes -> plain
val repr:  id -> adata -> range -> plain -> bytes

val makeAD: id -> StatefulPlain.history -> StatefulPlain.adata -> adata
val parseAD: id -> adata -> StatefulPlain.adata
val StatefulPlainToLHAEPlain: id -> StatefulPlain.history -> StatefulPlain.adata -> adata -> range -> StatefulPlain.plain -> plain
val LHAEPlainToStatefulPlain: id -> StatefulPlain.history -> StatefulPlain.adata -> adata -> range -> plain -> StatefulPlain.plain

val makeExtPad:  id -> adata -> range -> plain -> plain
val parseExtPad: id -> adata -> range -> plain -> plain Result

#if ideal
val widen: id -> adata -> range -> fragment -> fragment
#endif