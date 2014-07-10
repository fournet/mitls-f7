module DHGroup

open Bytes
open CoreKeys

type p   = bytes
type elt = bytes 
type g   = bytes
type q   = bytes

type preds = Elt of p * g * elt

let dhparams p g q: CoreKeys.dhparams = { p = p; g = g; q = q }

let genElement p g q: elt =
    let (_, (e, _)) = CoreDH.gen_key (dhparams p g q) in
#if verify
    Pi.assume (Elt(p,g,e));
#endif
    e

let checkElement (p:p) (g:g) (b:bytes): option<elt> =
    if CoreDH.check_element p g b then
#if verify
        Pi.assume(Elt(p,g,b));
#endif
        Some(b)
    else
        None
