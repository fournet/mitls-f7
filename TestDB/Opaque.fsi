module Opaque

open Bytes

type opaque //= { value:bytes; more:bytes } //= V of string

val v : opaque 

val show : opaque -> string
//val equal : opaque -> opaque -> bool