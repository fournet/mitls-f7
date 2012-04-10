module DataStream
open TLSInfo
open Bytes
open Error

val max_TLSPlaintext_fragment_length: int
val max_TLSCompressed_fragment_length: int
val max_TLSCipher_fragment_length: int
val fragmentLength: int

type range = int * int (* length range *)
val rangeSum: range -> range -> range
val splitRange: KeyInfo -> range -> range * range

type sbytes

val plain: KeyInfo -> range -> bytes -> sbytes
val repr:  KeyInfo -> range -> sbytes -> bytes

type stream
type delta

val delta:     KeyInfo -> stream -> range -> bytes -> delta
val deltaRepr: KeyInfo -> stream -> range -> delta -> bytes

val init: KeyInfo -> stream
val append: KeyInfo -> stream -> range ->
            delta -> stream

val split: KeyInfo -> stream -> range -> range ->
           delta -> delta * delta
val join: KeyInfo -> stream -> range -> delta -> 
          range -> delta -> delta

val contents:  KeyInfo -> stream -> range -> delta -> sbytes  
val construct: KeyInfo -> stream -> range -> sbytes -> delta