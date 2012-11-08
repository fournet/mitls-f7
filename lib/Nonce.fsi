module Nonce

open Bytes

val mkRandom: int -> bytes
val mkClientRandom: unit -> bytes
