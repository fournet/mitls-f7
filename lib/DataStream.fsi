module DataStream
open TLSInfo
open Bytes
open Error

type range = int * int (* length range *)

type stream
type delta

val init: KeyInfo -> stream
val append: KeyInfo -> stream -> range ->
            delta -> stream

val split: KeyInfo -> stream -> range -> range ->
           delta -> delta * delta

val delta: KeyInfo -> stream -> range -> bytes -> delta  

val deltaRepr: KeyInfo -> stream -> range -> delta -> bytes

