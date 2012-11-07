module DHGroup

open Bytes

type p   = bytes
type elt = bytes 
type g   = elt

type secret = Key of bytes 

let private dhparams p g: CoreKeys.dhparams = { p = p; g = g }

let genKey p g: elt * secret =
    let ((x, _), (e, _)) = CoreDH.gen_key (dhparams p g)
    (e, Key x)
   
let leak (p:p) (g:g) (gx:elt) (Key x) = x