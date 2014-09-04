#light "off"

module DH

open Bytes
open DHGroup
open CoreKeys

type secret = Key of bytes 

#if ideal
type honest_entry = (dhparams * elt)
let honest_log = ref([]: list<honest_entry>)
let log = ref []
#if verify
let honest dhp gx = failwith "only used in ideal implementation, unverified"
#else
let honest dhp gx = List.exists (fun el-> el = (dhp,gx)) !honest_log 
#endif
#endif

type predHE = HonestExponential of dhparams * elt

let genKey p g: elt * secret =
    let ((x, _), (ce, _)) = CoreDH.gen_key p g in
    //let eoption = DHGroup.checkElement p g ce
    //let e = match eoption with
    //        | None -> Error.unexpected("Invalid DH generator") //failwith "Invalid DH generator"
    //        | Some b -> b
    let e=ce in
    #if ideal
    #if verify
    Pi.assume(Elt(p,g,e));
    Pi.assume(HonestExponential(p,g,e));
    #else
    honest_log := (p,g,e)::!honest_log;
    #endif
    #endif
    (e, Key (x))

#if ideal
// We maintain a log for looking up good ms values using their msId
type entry = p* g * elt * elt * PMS.dhpms
let rec assoc (p:p) (g:g) (gx:elt) (gy:elt) entries: option<PMS.dhpms> = 
    match entries with 
    | []                      -> None 
    | (p',g',gx',gy', pms)::entries when p = p' && g=g' && gx=gx' && gy=gy' -> Some(pms) 
    | _::entries              -> assoc p g gx gy entries

//SZ Never used
let safeDH (p:p) (g:g) (gx:elt) (gy:elt): bool = 
    honest p g gx && honest p g gy && goodPP p g
#endif

let leak   (p:p) (g:g) (gx:elt) (Key(b)) = b
let coerce (p:p) (g:g) (gx:elt) b = Key(b)

let serverGen () =
    let (p,g,q) = default_pp() in
    let (e,s) = genKey p g in 
    (p,g,e,s)

let clientGenExp p g gs =
    let (gc,c) = genKey p g in
    let (Key ck) = c in
    let pms = (CoreDH.agreement (dhparams p g None) (ck) (gs)) in
    //#begin-ideal
    #if ideal
    if honest p g gs && honest p g gc && goodPP p g
    then 
      match assoc p g gs gc !log with
      | Some(pms) -> (gc,c,pms)
      | None -> 
                 let pms=PMS.sampleDH p g gs gc in
                 log := (p,g,gs,gc,pms)::!log;
                 (gc,c,pms)
    else 
      (Pi.assume(DHGroup.Elt(p,g,pms)); //use checkElement instead
      let dpms = PMS.coerceDH p g gs gc pms in
      (gc,c, dpms))
    //#end-ideal 
    #else
    let dpms = PMS.coerceDH p g gs gc pms in
    (gc,c, dpms)
    #endif

let serverExp p g gs gc sk =
    let (Key s) = sk in
    let pms = (CoreDH.agreement (dhparams p g None) (s) (gc)) in
    //#begin-ideal
    #if ideal
    if honest p g gs && honest p g gc && goodPP p g
    then
      match assoc p g gs gc !log with
      | Some(pms) -> pms
      | None ->
                 let pms=PMS.sampleDH p g gs gc in
                 log := (p,g,gs,gc,pms)::!log;
                 pms
    else
      (Pi.assume(DHGroup.Elt(p,g,pms)); //use checkElement instead
      let dpms = PMS.coerceDH p g gs gc pms in
      dpms)
    //#end-ideal
    #else
    let dpms = PMS.coerceDH p g gs gc pms in
    dpms
    #endif
