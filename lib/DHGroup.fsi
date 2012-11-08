module DHGroup

open Bytes

type p = bytes
type elt = bytes
type g = elt

val genElement: p -> g -> elt