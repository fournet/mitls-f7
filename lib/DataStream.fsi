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
type stream
type sbytes
type delta = sbytes


val init: KeyInfo -> stream
val append: KeyInfo -> stream -> range ->
            delta -> stream

val split: KeyInfo -> stream -> range -> range ->
           delta -> delta * delta
val join: KeyInfo -> stream -> range -> delta -> 
          range -> delta -> delta

val plain: KeyInfo -> range -> bytes -> sbytes
val repr:  KeyInfo -> range -> sbytes -> bytes

val delta: KeyInfo -> stream -> range -> bytes -> delta  

val deltaRepr: KeyInfo -> stream -> range -> delta -> bytes