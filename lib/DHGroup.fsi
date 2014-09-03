#light "off"

module DHGroup

open Bytes

type p   = bytes
type q   = bytes
type elt = bytes
type g   = elt

type preds = Elt of p * g * bytes
type predPP = PP of p * g

val genElement: p -> g -> option<q> -> elt
val checkElement: p -> g -> bytes -> option<elt>
val genElement  : p -> g -> elt
val checkParams : p -> g -> elt option
val dhparams: p -> g -> option<q> -> CoreKeys.dhparams

val dhparams    : p -> g -> q -> CoreKeys.dhparams