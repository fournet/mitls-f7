module Sig 

open Bytes
open TLSConstants



(* ------------------------------------------------------------------------ *)
type alg   = sigAlg * hashAlg

type text = bytes
type sigv = bytes 

(* ------------------------------------------------------------------------ *)
type skey = { skey : CoreSig.sigskey * hashAlg }
type pkey = { pkey : CoreSig.sigpkey * hashAlg }

let create_skey (h : hashAlg) (p : CoreSig.sigskey) = { skey = (p, h) }
let create_pkey (h : hashAlg) (p : CoreSig.sigpkey) = { pkey = (p, h) }

let repr_of_skey { skey = skey } = skey
let repr_of_pkey { pkey = pkey } = pkey

let sigalg_of_skeyparams = function
    | CoreSig.SK_RSA _ -> SA_RSA
    | CoreSig.SK_DSA _ -> SA_DSA

let sigalg_of_pkeyparams = function
    | CoreSig.PK_RSA _ -> SA_RSA
    | CoreSig.PK_DSA _ -> SA_DSA

#if ideal
let log = ref []
let honest_log = ref []

let rec assoc hll pk =
    match hll with
        (pk',sk')::hll_tail when pk=pk' -> Some ()
      | _::hll_tail -> assoc hll_tail pk
      | [] -> None


let rec pk_of_log sk hll =
    match hll with
        (pk',sk')::hll_tail when sk=sk' -> Some (pk')
      | _::hll_tail -> pk_of_log sk hll_tail
      | [] -> None

let pk_of (sk:skey) = 
    fst ( List.find (fun el -> snd el=sk) !honest_log )  

let honest pk =
    List.exists (fun el -> fst el=pk) !honest_log

#endif

(* ------------------------------------------------------------------------ *)
let sign (a : alg) (sk : skey) (t : text) : sigv =
    let asig, ahash = a in
    let { skey = (kparams, khash) } = sk in

    if ahash <> khash then
        Error.unexpectedError
            (sprintf "Sig.sign: requested sig-hash = %A, but key requires %A"
                ahash khash)
    if asig <> sigalg_of_skeyparams kparams then
        Error.unexpectedError
            (sprintf "Sig.sign: requested sig-algo = %A, but key requires %A"
                asig (sigalg_of_skeyparams kparams))

    let signature = match khash with
    | NULL    -> CoreSig.sign None                     kparams t
    | MD5     -> CoreSig.sign (Some CoreSig.SH_MD5)    kparams t
    | SHA     -> CoreSig.sign (Some CoreSig.SH_SHA1  ) kparams t
    | SHA256  -> CoreSig.sign (Some CoreSig.SH_SHA256) kparams t
    | SHA384  -> CoreSig.sign (Some CoreSig.SH_SHA384) kparams t
    | MD5SHA1 ->
        let t = HASH.hash MD5SHA1 t in
            CoreSig.sign None kparams t
    #if ideal
    if honest (pk_of sk) then 
        log := (a, pk_of sk,signature, t)::!log;
    #endif
    signature
(* ------------------------------------------------------------------------ *)
let verify (a : alg) (pk : pkey) (t : text) (s : sigv) =
    let asig, ahash = a in
    let  { pkey = (kparams, khash) } = pk in

    if ahash <> khash then
        Error.unexpectedError
            (sprintf "Sig.verify: requested sig-hash = %A, but key requires %A"
                ahash khash)
    if asig <> sigalg_of_pkeyparams kparams then
        Error.unexpectedError
            (sprintf "Sig.verify: requested sig-algo = %A, but key requires %A"
                asig (sigalg_of_pkeyparams kparams))

    let result = match khash with
    | NULL    -> CoreSig.verify None                     kparams t s
    | MD5     -> CoreSig.verify (Some CoreSig.SH_MD5)    kparams t s
    | SHA     -> CoreSig.verify (Some CoreSig.SH_SHA1  ) kparams t s
    | SHA256  -> CoreSig.verify (Some CoreSig.SH_SHA256) kparams t s
    | SHA384  -> CoreSig.verify (Some CoreSig.SH_SHA384) kparams t s
    | MD5SHA1 ->
        let t = HASH.hash MD5SHA1 t in
            CoreSig.verify None kparams t s
    #if ideal
    let result = if honest pk 
                    then result && (exists (fun el -> el=(a, pk, s, t)) !log)
                    else result 
    #endif
    result

(* ------------------------------------------------------------------------ *)
let gen (a:alg) : pkey * skey =
    let asig, ahash  = a in
    let (pkey, skey) =
        match asig with
        | SA_RSA -> CoreSig.gen CoreSig.SA_RSA
        | SA_DSA -> CoreSig.gen CoreSig.SA_DSA
        | _      -> failwith "unsupported / TODO"
    in
        #if ideal
        honest_log := ({ pkey = (pkey, ahash) }, { skey = (skey, ahash) })::!honest_log;
        #endif
        ({ pkey = (pkey, ahash) }, { skey = (skey, ahash) })
