module DHGroup

open Bytes
open CoreKeys

type p   = bytes
type elt = bytes 
type g   = elt

type preds = Elt of p * elt

let dhparams p g: CoreKeys.dhparams = { p = p; g = g }

let genElement p g: elt =
    let (_, (e, _)) = CoreDH.gen_key (dhparams (p) (g)) in
#if verify
    Pi.assume (Elt(p,e));
#endif
    e

let checkElement (p:p) (b:bytes) :elt option =
    if CoreDH.check_element (p) (b) then
#if verify
        Pi.assume(Elt(p,b));
#endif
        Some(b)
    else
        None
