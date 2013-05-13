module AppFragment
open Bytes
open TLSInfo
open Range
open DataStream

type fragment
val fragment: epoch -> stream -> range -> delta -> fragment * stream
val delta: epoch -> stream -> range -> fragment -> delta * stream
type plain = fragment

val plain: id -> range -> bytes -> fragment
val repr:  id -> range -> fragment -> bytes

#if ideal
val widen: epoch -> range -> fragment -> fragment
#endif