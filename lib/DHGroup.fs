#light "off"

module DHGroup

open Bytes
open CoreKeys
open Error
open TLSError

type elt = bytes

#if ideal
type preds = Elt of dhparams * elt
type predPP = PP of dhparams

let goodPP_log = ref([]: list<dhparams>)
#if verify
let goodPP (dhp:dhparams) : bool = failwith "only used in ideal implementation, unverified"
#else
let goodPP dhp =  List.memr !goodPP_log dhp
#endif

let pp (dhp:dhparams) : dhparams =
#if verify
    Pi.assume(PP(dhp));
#else
    goodPP_log := (dhp ::!goodPP_log);
#endif
    dhp
#endif



let genElement dhp: elt =
    let (_, e) = CoreDH.gen_key dhp in
#if verify
    Pi.assume (Elt(dhp,e));
#endif
    e

let checkParams dhdb minSize p g =
    match CoreDH.check_params dhdb minSize p g with
    | Error(x) -> Error(AD_insufficient_security,x)
    | Correct(res) ->
        let (dhdb,dhp) = res in
#if ideal
        let dhp = pp(dhp) in
        let rp = dhp.dhp in
        let rg = dhp.dhg in
        if rp <> p || rg <> g then
            failwith "Trusted code returned inconsitent value"
        else
#endif
        correct (dhdb,dhp)

let checkElement dhp (b:bytes): option<elt> =
    if CoreDH.check_element dhp b then
        (
#if verify
        Pi.assume(Elt(dhp,b));
#endif
        Some(b))
    else
        None

let defaultDHparams file dhdb minSize =
    let (dhdb,dhp) = CoreDH.load_default_params file dhdb minSize in
#if ideal
    let dhp = pp(dhp) in
#endif
    (dhdb,dhp)