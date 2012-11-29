module AEADPlain
open Bytes
open TLSInfo

type adata = bytes
type fragment
type plain = fragment

val plain: epoch -> adata -> range -> bytes -> plain
val repr:  epoch -> adata -> range -> plain -> bytes

//val contents:  epoch -> range -> data -> AEADPlain -> fragment
//val construct: epoch -> range -> data -> fragment -> AEADPlain

val makeAD: epoch -> StatefulPlain.history -> StatefulPlain.adata -> adata
val parseAD: epoch -> adata -> StatefulPlain.adata
val StatefulPlainToAEADPlain: epoch -> StatefulPlain.history -> StatefulPlain.adata -> range -> StatefulPlain.plain -> plain
val AEADPlainToStatefulPlain: epoch -> StatefulPlain.history -> StatefulPlain.adata -> range -> plain -> StatefulPlain.plain