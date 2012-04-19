module Fragment
open Bytes
open TLSInfo
open DataStream

type fragment
val fragment: epoch -> stream -> range -> delta -> fragment * stream
val delta: epoch -> stream -> range -> fragment -> delta * stream

val fragmentRepr: epoch -> range -> fragment -> bytes
val fragmentPlain: epoch -> range -> bytes -> fragment
