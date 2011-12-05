module Formats

open Bytes
open Error

(* val split_at_most: bytes -> int -> (bytes * bytes) *)

type preContentType =
    | Change_cipher_spec
    | Alert
    | Handshake
    | Application_data
    | UnknownCT

type ContentType = preContentType

val bytes_of_seq: int -> bytes

val bytes_of_contentType: ContentType -> bytes
val contentType_of_bytes: bytes -> ContentType
val CTtoString: ContentType -> string

val vlenBytes_of_bytes: int -> bytes -> bytes
val bytes_of_vlenBytes: int -> bytes -> (bytes * bytes) Result

//val splitList: bytes -> int list -> bytes list