module AppFragment
open Bytes
open TLSInfo
open DataStream

type fragment
val fragment: epoch -> stream -> range -> delta -> fragment * stream
val delta: epoch -> stream -> range -> fragment -> delta * stream

type plain = fragment

val plain: epoch -> range -> bytes -> fragment
val repr: epoch -> range -> fragment -> bytes
