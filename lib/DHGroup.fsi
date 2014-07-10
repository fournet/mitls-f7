module DHGroup

open Bytes

type p   = bytes
type q   = bytes
type elt = bytes
type g   = elt

type preds = Elt of p * g * bytes

val genElement: p -> g -> q option -> elt
val checkElement: p -> g -> bytes -> elt option
val dhparams: p -> g -> q option -> CoreKeys.dhparams
