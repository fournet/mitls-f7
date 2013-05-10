module DataStream
open TLSInfo
open Bytes
open Error
open TLSError
open Range

val splitRange: epoch -> range -> range * range

type stream
type delta

val init: id -> stream
val createDelta: id -> stream -> range -> rbytes -> delta
val append: id -> stream -> range -> delta -> stream
val split: id -> stream -> range -> range -> delta -> delta * delta
val deltaPlain: id -> stream -> range -> rbytes -> delta
val deltaRepr: id -> stream -> range -> delta -> rbytes
#if ideal
val widen: id -> stream -> range -> range -> delta -> delta
#endif
