module Formats

open Bytes
open CipherSuites
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

val byte_of_contentType: ContentType -> byte
val contentType_of_byte: byte -> ContentType
val CTtoString: ContentType -> string

val vlenBytes_of_bytes: int -> bytes -> bytes
val bytes_of_vlenBytes: int -> bytes -> (bytes * bytes) Result

//val splitList: bytes -> int list -> bytes list