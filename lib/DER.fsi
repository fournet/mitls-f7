module DER

open Bytes

type dervalue =
    | Bool       of bool
    | Bytes      of byte[]
    | Utf8String of string
    | Sequence   of dervalue list

exception DerEncodingFailure

val encode : dervalue -> byte[]
val decode : byte[] -> dervalue option
