module Formats

open Bytes
open Error

(* val split_at_most: bytes -> int -> (bytes * bytes) *)

type preContentType =
    | Change_cipher_spec
    | Alert
    | Handshake
    | Application_data

type ContentType = preContentType 
val bytes_of_seq: int -> bytes
val seq_of_bytes: bytes -> int

val ctBytes: ContentType -> bytes
val parseCT: bytes -> ContentType Result
val CTtoString: ContentType -> string

val vlbytes: int -> bytes -> bytes
val vlsplit: int -> bytes -> (bytes * bytes) Result
val vlparse: int -> bytes -> bytes Result

//val splitList: bytes -> int list -> bytes list