module DER

open Bytes

type dervalue =
    | Bool       of bool
    | Bytes      of bytes
    | Utf8String of string
    | Sequence   of dervalue list

exception DerEncodingFailure

val encode : dervalue -> bytes
val decode : bytes -> dervalue option
