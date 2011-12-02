module HMAC

open Bytes
open Algorithms

type key = bytes
type data = bytes
type mac = bytes

val HMAC: hashAlg -> key -> data -> mac
val HMACVERIFY: hashAlg -> key -> data -> mac -> bool