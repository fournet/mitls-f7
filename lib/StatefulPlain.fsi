module StatefulPlain
open Bytes
open TLSConstants
open TLSInfo
open Range

type adata = bytes

type fragment
type prehistory = (adata * range * fragment) list
type history  = (nat * prehistory)
type plain = fragment

//------------------------------------------------------------------------------
val plain: epoch -> history -> adata -> range -> bytes -> plain
val reprFragment:  epoch -> adata -> range -> fragment -> bytes
val repr:  epoch -> history -> adata -> range -> plain -> bytes

//------------------------------------------------------------------------------
val emptyHistory: epoch -> history
val extendHistory: epoch -> adata -> history -> range -> fragment -> history


val makeAD: epoch -> ContentType -> adata
val RecordPlainToStAEPlain: epoch -> ContentType -> TLSFragment.history -> history -> range -> TLSFragment.plain -> plain
val StAEPlainToRecordPlain: epoch -> ContentType -> TLSFragment.history -> history -> range -> plain -> TLSFragment.plain

#if ideal
val widen: epoch -> adata -> range -> fragment -> fragment
#endif