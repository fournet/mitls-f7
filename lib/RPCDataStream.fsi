module RPCDataStream
open TLSInfo
open Bytes
open Error

val max_TLSCipher_fragment_length: nat
type range = nat * nat (* length range *)
type rbytes = bytes
val rangeSum: range -> range -> range
val splitRange: epoch -> range -> range * range

type stream
type delta

val stream_to_bytes: epoch -> stream -> bytes

val split: epoch -> stream -> range -> range -> delta -> delta * delta
val deltaPlain:         epoch -> stream -> range -> rbytes -> delta
val deltaRepr:     epoch -> stream -> range -> delta -> rbytes
