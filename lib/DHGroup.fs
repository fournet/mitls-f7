module DHGroup

open Bytes

type p   = bytes
type elt = bytes 
type g   = elt

let private dhparams p g: CoreKeys.dhparams = { p = p; g = g }

let genElement p g: elt =
    let (_, (e, _)) = CoreDH.gen_key (dhparams p g) in
    e
