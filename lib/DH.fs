module DH

open Bytes
open DHGroup

type secret = Key of bytes 

let private pp (pg:CoreKeys.dhparams) : p * g = pg.p, pg.g
let private dhparams p g: CoreKeys.dhparams = { p = p; g = g }

let gen_pp()     = pp (CoreDH.gen_params())
let default_pp() = pp (CoreDH.load_default_params())

let genKey p g: elt * secret =
    let ((x, _), (e, _)) = CoreDH.gen_key (dhparams p g)
    (e, Key x)

let exp p g (gx:elt) (gy:elt) (Key x) : CRE.dhpms =
    let pms = CoreDH.agreement (dhparams p g) x gy in
    CRE.coerceDH p g gx gy pms
