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
val plain: id -> history -> adata -> range -> bytes -> plain
val reprFragment:  id -> adata -> range -> fragment -> bytes
val repr:  id -> history -> adata -> range -> plain -> bytes

//------------------------------------------------------------------------------
val emptyHistory: id -> history
val extendHistory: id -> adata -> history -> range -> fragment -> history


val makeAD: id -> ContentType -> adata
val RecordPlainToStAEPlain: epoch -> ContentType -> adata -> TLSFragment.history -> history -> range -> TLSFragment.plain -> plain
val StAEPlainToRecordPlain: epoch -> ContentType -> adata -> TLSFragment.history -> history -> range -> plain -> TLSFragment.plain

#if ideal
val widen: id -> adata -> range -> fragment -> fragment
#endif
