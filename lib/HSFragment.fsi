module HSFragment
open Bytes
open TLSInfo
open Range

type stream

type fragment
type plain = fragment

val fragmentRepr: epoch -> range -> fragment -> bytes
val fragmentPlain: epoch -> range -> bytes -> fragment

val extend: epoch -> stream -> range -> fragment -> stream
val init: epoch -> stream

val reStream: epoch -> stream -> range -> plain -> stream -> plain

#if ideal
val widen: epoch -> range -> range -> fragment -> fragment
#endif

 