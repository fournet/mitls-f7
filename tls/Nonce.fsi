#light "off"

module Nonce

open Bytes
open TLSConstants

val random: nat -> bytes
val mkHelloRandom: ProtocolVersion -> bytes

val noCsr: bytes
