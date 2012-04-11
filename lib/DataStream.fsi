module DataStream
open TLSInfo
open Bytes
open Error

val max_TLSPlaintext_fragment_length: nat
val max_TLSCompressed_fragment_length: nat
val max_TLSCipher_fragment_length: nat
val fragmentLength: nat

type range = nat * nat (* length range *)
type rbytes = bytes
val rangeSum: range -> range -> range
val splitRange: KeyInfo -> range -> range * range

type sbytes

val plain: KeyInfo -> range -> rbytes -> sbytes
val repr:  KeyInfo -> range -> sbytes -> rbytes

type stream
type predelta
type delta = predelta

val delta:     KeyInfo -> stream -> range -> rbytes -> delta
val deltaRepr: KeyInfo -> stream -> range -> delta -> rbytes

val init: KeyInfo -> stream
val append: KeyInfo -> stream -> range ->
            delta -> stream

val split: KeyInfo -> stream -> range -> range ->
           delta -> delta * delta
val join: KeyInfo -> stream -> range -> delta -> 
          range -> delta -> delta

val contents:  KeyInfo -> stream -> range -> delta -> sbytes  
val construct: KeyInfo -> stream -> range -> sbytes -> delta