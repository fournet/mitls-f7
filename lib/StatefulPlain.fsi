module StatefulPlain
open Bytes
open TLSConstants
open TLSInfo

type adata = bytes

type fragment
type prehistory = (adata * range * fragment) list
type history  = (nat * prehistory)
type plain = fragment

//------------------------------------------------------------------------------
val plain: epoch -> history -> adata -> range -> bytes -> plain
val repr:  epoch -> history -> adata -> range -> plain -> bytes

//------------------------------------------------------------------------------
val emptyHistory: epoch -> history
val addToHistory: epoch -> adata -> history -> range -> plain -> history

//val contents:  epoch -> history -> adata -> range -> statefulPlain -> Fragment.fragment
//val construct: epoch -> history -> adata -> range -> Fragment.fragment -> statefulPlain

val makeAD: epoch -> ContentType -> adata
val parseAD: epoch -> adata -> ContentType
val RecordPlainToStAEPlain: epoch -> ContentType -> TLSFragment.history -> history -> range -> TLSFragment.plain -> plain
val StAEPlainToRecordPlain: epoch -> ContentType -> TLSFragment.history -> history -> range -> plain -> TLSFragment.plain
