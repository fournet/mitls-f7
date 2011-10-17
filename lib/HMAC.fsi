module HMAC

open Data
open Algorithms
open Error_handling

type macKey = bytes
type text  = bytes
type mac = bytes

val HMAC: hashAlg -> macKey -> text -> mac Result
val HMACVERIFY: hashAlg -> macKey -> text -> mac -> unit Result