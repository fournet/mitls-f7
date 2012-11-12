module Nonce

open Bytes

val mkRandom: int -> bytes
val mkHelloRandom: unit -> bytes
