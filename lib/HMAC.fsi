module HMAC

open Data
open Algorithms
open Error_handling
open TLSPlain

type macKey = bytes

val HMAC: hashAlg -> macKey -> mac_plain -> mac Result
val HMACVERIFY: hashAlg -> macKey -> mac_plain -> mac -> unit Result