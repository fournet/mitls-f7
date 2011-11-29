module HMAC

open Bytes
open Algorithms
open Error

type key = bytes
type data = bytes
type mac = bytes

val HMAC: hashAlg -> key -> data -> mac Result
val HMACVERIFY: hashAlg -> key -> data -> mac -> unit Result