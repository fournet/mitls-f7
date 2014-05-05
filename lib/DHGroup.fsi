module DHGroup

open Bytes

type preds = Elt of bytes * bytes

type p = bytes
type elt = bytes
type g = elt

val genElement: p -> g -> elt
val checkElement: p -> bytes -> elt option
val dhparams: p:p -> g -> CoreKeys.dhparams