module DH

open Bytes
open DHGroup

type secret = Key of bytes 

#if ideal
// We maintain 4 logs:
// - a log DH parameters returned by pp
// - a log of honest gx and gy values
// - a log for looking up good pms values using gx and gy values
let goodPP_log = ref []
let honest_log = ref []
let log = ref []
let goodPP dhparams =  List.exists (fun el-> el = dhparams) !goodPP_log
let honest gx = List.exists (fun el-> el = gx) !honest_log 
#endif

let private pp (pg:CoreKeys.dhparams) : p * g = 
    let dhparams = abytes pg.p, abytes pg.g
    #if ideal
    goodPP_log := dhparams ::!goodPP_log
    #endif
    dhparams
    
let private dhparams p g: CoreKeys.dhparams = { p = cbytes p; g = cbytes g }

let gen_pp()     = pp (CoreDH.gen_params())
     
let default_pp() = pp (CoreDH.load_default_params())

let genKey p g: elt * secret =
    let ((x, _), (e, _)) = CoreDH.gen_key (dhparams p g)
    #if ideal
    honest_log := (abytes e)::!honest_log
    #endif
    (abytes e, Key (abytes x))

let exp p g (gx:elt) (gy:elt) (Key x) : PMS.dhpms =
    let pms = abytes (CoreDH.agreement (dhparams p g) (cbytes x) (cbytes gy)) in
    //#begin-ideal
    #if ideal
    if honest gy && honest gx && goodPP (p,g) 
    then 
    //MK should use assoc here
      match List.tryFind (fun el -> fst el=(gx,gy)) !log with
      | Some(_,pms) -> pms
      | None -> 
                 let pms=PMS.sampleDH p g gx gy
                 log := ((gx,gy),pms)::!log;
                 pms 
    else PMS.coerceDH p g gx gy pms
    //#end-ideal 
    #else
    PMS.coerceDH p g gx gy pms
    #endif