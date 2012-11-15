module DataStream

open TLSInfo
open Bytes
open Error

val max_TLSPlaintext_fragment_length  : nat
val max_TLSCompressed_fragment_length : nat
val max_TLSCipher_fragment_length     : nat
val fragmentLength                    : nat

type range  = nat * nat (* length range *)
type rbytes = bytes

val rangeSum   : range -> range -> range
val splitRange : epoch -> range -> range * range

type stream
type delta

val init        : epoch -> stream
val createDelta : epoch -> stream -> range -> rbytes -> delta
val append      : epoch -> stream -> range -> delta -> stream
val split       : epoch -> stream -> range -> range -> delta -> delta * delta

val deltaPlain  : epoch -> stream -> range -> rbytes -> delta
val deltaRepr   : epoch -> stream -> range -> delta  -> rbytes
