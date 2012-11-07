module DH

open Bytes
open DHGroup

let private pp (pg:CoreKeys.dhparams) : p * g = pg.p, pg.g
let private dhparams p g: CoreKeys.dhparams = { p = p; g = g }

let gen_pp()     = pp (CoreDH.gen_params())
let default_pp() = pp (CoreDH.load_default_params())

let exp p g (gx:elt) (gy:elt) x : CRE.dhpms =
    let xb = DHGroup.leak p g gx x in
    let pms = CoreDH.agreement (dhparams p g) xb gy in
    CRE.coerceDH p g gx gy pms
