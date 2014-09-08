#light "off"

module DHGroup

open Bytes
open CoreKeys

type p   = bytes
type elt = bytes 
type g   = bytes
type q   = bytes

type preds = Elt of p * g * elt
type predPP = PP of p * g

let dhparams p g q: CoreKeys.dhparams = { p = p; g = g; q = q }

let genElement p g: elt =
    let (_, (e, _)) = CoreDH.gen_key p g in
#if verify
    Pi.assume (Elt(p,g,e));
#endif
    e

let checkParams (p:p) (g:g): elt option =
    if CoreDH.check_params p g then
#if verify
        Pi.assume(Elt(p,g,g));
#endif
        Some(g)
    else
        None

let checkElement (p:p) (g:g) (b:bytes): option<elt> =
    if CoreDH.check_element p g b then
        (
#if verify
        Pi.assume(Elt(p,g,b));
#endif
        Some(b))
    else
        None
