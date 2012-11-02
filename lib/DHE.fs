module DHE

open Bytes
open TLSInfo

(* public parameters *)

type p   = bytes
type elt = bytes 
type g   = elt 

let private pp (pg:CoreKeys.dhparams) : p * g = pg.p, pg.g 
let private dhparams p g: CoreKeys.dhparams = { p = p; g = g }

let gen_pp()     = pp (CoreDH.gen_params())
let default_pp() = pp (CoreDH.load_default_params())

(* exponents and exponentials *) 

type secret = Key of bytes 

let genKey p g: elt * secret =
    let ((x, _), (e, _)) = CoreDH.gen_key (dhparams p g)
    (e, Key x)

(* DH shared secrets as pms *)

type pms = { pms : elt }

let exp p g (gx:elt) (gy:elt) (Key x) : pms =
    { pms = CoreDH.agreement (dhparams p g) x gy }

let sample (p:bytes) (g:elt) (gx:elt) (gy:elt) : pms =
    { pms = mkRandom 32}

let leak (si : SessionInfo) pms = pms.pms
