module DataStream
open TLSInfo
open Bytes
open Error

val max_TLSCipher_fragment_length: nat
type range = nat * nat (* length range *)
type rbytes = bytes
val rangeSum: range -> range -> range
val splitRange: KeyInfo -> range -> range * range

type stream
type delta
val init: KeyInfo -> stream
val createDelta:   KeyInfo -> stream -> range -> rbytes -> delta
val append: KeyInfo -> stream -> range -> delta -> stream
val split: KeyInfo -> stream -> range -> range -> delta -> delta * delta
val join: KeyInfo -> stream -> range -> delta -> range -> delta -> delta

val deltaPlain:         KeyInfo -> stream -> range -> rbytes -> delta
val deltaRepr:     KeyInfo -> stream -> range -> delta -> rbytes

