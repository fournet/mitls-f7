module DH

open Bytes
open DHGroup

type secret = Key of bytes 

#if ideal
let honest_log = ref []
let honest gx = exists (fun el-> el = gx) !honest_log 
let log = ref []
let goodPP_log = ref []
let goodPP dhparams =  exists (fun el-> el = dhparams) !goodPP_log
#endif

let private pp (pg:CoreKeys.dhparams) : p * g = 
    let dhparams = pg.p, pg.g
    #if ideal
    goodPP_log := dhparams ::!goodPP_log
    #endif
    dhparams
    
let private dhparams p g: CoreKeys.dhparams = { p = p; g = g }

let gen_pp()     = pp (CoreDH.gen_params())
     
let default_pp() = pp (CoreDH.load_default_params())

let genKey p g: elt * secret =
    let ((x, _), (e, _)) = CoreDH.gen_key (dhparams p g)
    #if ideal
    honest_log := e::!honest_log
    #endif
    (e, Key x)

let exp p g (gx:elt) (gy:elt) (Key x) : CRE.dhpms =
    let pms = CoreDH.agreement (dhparams p g) x gy in
    #if ideal
    if honest gy && honest gx && goodPP (p,g) 
    then 
      match tryFind (fun el -> fst el=(gx,gy)) !log with
      | Some(_,pms) -> pms
      | None -> 
                 let pms=CRE.sampleDH p g gx gy
                 log := ((gx,gy),pms)::!log;
                 pms 
    else CRE.coerceDH p g gx gy pms 
    #else
    CRE.coerceDH p g gx gy pms
    #endif