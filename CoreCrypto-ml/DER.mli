module DER

open Bytes

type dervalue =
    | Bool       of bool
    | Bytes      of bytes
    | Utf8String of string
    | Sequence   of dervalue list

//AP exception DerEncodingFailure // so we can use it in typechecking code

val encode : dervalue -> bytes
val decode : bytes -> dervalue option
