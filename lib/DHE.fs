module DHE

open Bytes
open TLSInfo

(* public parameters *)

type p   = bytes
type elt = bytes 
type g   = elt 
type pp  = p * g  
type y   = elt


let private pp (pg:CoreKeys.dhparams) : pp = pg.p, pg.g 
let private dhparams p g: CoreKeys.dhparams = { p = p; g = g }

let gen_pp()     = pp (CoreDH.gen_params())
let default_pp() = pp (CoreDH.load_default_params())

(* exponents and exponentials *) 

type x = Key of bytes 

let genKey p g: x * elt =
    let ((x, _), (e, _)) = CoreDH.gen_key (dhparams p g)
    (Key x, e)

(* DH shared secrets as pms *)

type pms = { pms : elt }

let genPMS (si : SessionInfo) p g (Key x) (y : elt) : pms =
    { pms = CoreDH.agreement (dhparams p g) x y }

let leak (si : SessionInfo) pms = pms.pms
