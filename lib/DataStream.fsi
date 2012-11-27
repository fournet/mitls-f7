module DataStream
open TLSInfo
open Bytes
open Error

val splitRange: epoch -> range -> range * range

type stream
type delta

val init: epoch -> stream
val createDelta: epoch -> stream -> range -> rbytes -> delta
val append: epoch -> stream -> range -> delta -> stream
val split: epoch -> stream -> range -> range -> delta -> delta * delta
val deltaPlain: epoch -> stream -> range -> rbytes -> delta
val deltaRepr: epoch -> stream -> range -> delta -> rbytes
