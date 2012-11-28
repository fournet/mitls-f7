module HSFragment
open Bytes
open TLSInfo

type stream

type fragment
type plain = fragment

val fragmentRepr: epoch -> range -> fragment -> bytes
val fragmentPlain: epoch -> range -> bytes -> fragment

val extend: epoch -> stream -> range -> fragment -> stream
val init: epoch -> stream

 