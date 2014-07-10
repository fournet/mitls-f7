#light "off"

module DHGroup

open Bytes

type p   = bytes
type q   = bytes
type elt = bytes
type g   = elt

type preds = Elt of p * g * bytes

val genElement: p -> g -> option<q> -> elt
val checkElement: p -> g -> bytes -> option<elt>
val dhparams: p -> g -> option<q> -> CoreKeys.dhparams
