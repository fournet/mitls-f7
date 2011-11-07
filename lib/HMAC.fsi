module HMAC

open Data
open Algorithms
open Error_handling

val HMAC: hashAlg -> bytes -> bytes -> bytes Result
val HMACVERIFY: hashAlg -> bytes -> bytes -> bytes -> unit Result