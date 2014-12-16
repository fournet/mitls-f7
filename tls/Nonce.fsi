#light "off"

module Nonce

open Bytes

val random: nat -> bytes
val mkHelloRandom: unit -> bytes

val noCsr: bytes
