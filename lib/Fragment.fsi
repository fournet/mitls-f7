module Fragment
open Bytes
open TLSInfo
open DataStream

type fragment
val fragment: KeyInfo -> stream -> range -> delta -> fragment * stream
val delta: KeyInfo -> stream -> range -> fragment -> delta * stream

val fragmentRepr: KeyInfo -> range -> fragment -> bytes
val fragmentPlain: KeyInfo -> range -> bytes -> fragment
