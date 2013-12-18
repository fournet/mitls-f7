module AppFragment
open Bytes
open TLSInfo
open Range
open DataStream
open TLSError

type preFragment
type fragment = preFragment
val fragment: epoch -> stream -> range -> delta -> fragment * stream
val delta: epoch -> stream -> range -> fragment -> delta * stream
type plain = fragment

val plain: id -> range -> bytes -> fragment
val repr:  id -> range -> fragment -> bytes

val makeExtPad:  id -> range -> fragment -> fragment
val parseExtPad: id -> range -> fragment -> fragment Result

#if ideal
val widen: id -> range -> fragment -> fragment
#endif