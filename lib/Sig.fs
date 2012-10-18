module Sig 

open Bytes
open TLSConstants

(* ------------------------------------------------------------------------ *)
type chash = hashAlg list
type alg   = sigAlg * chash

type text = bytes
type sigv = bytes 

(* ------------------------------------------------------------------------ *)
type skey = { skey : CoreSig.sigskey * chash }
type pkey = { pkey : CoreSig.sigpkey * chash }

let create_skey (h : chash) (p : CoreSig.sigskey) = { skey = (p, h) }
let create_vkey (h : chash) (p : CoreSig.sigpkey) = { pkey = (p, h) }

let repr_of_skey { skey = skey } = skey
let repr_of_pkey { pkey = pkey } = pkey

let sigalg_of_skeyparams = function
    | CoreSig.SK_RSA _ -> SA_RSA
    | CoreSig.SK_DSA _ -> SA_DSA

let sigalg_of_pkeyparams = function
    | CoreSig.PK_RSA _ -> SA_RSA
    | CoreSig.PK_DSA _ -> SA_DSA

(* ------------------------------------------------------------------------ *)
let cnvhash = function
    | MD5    -> CoreSig.SH_MD5
    | SHA    -> CoreSig.SH_SHA1
    | SHA256 -> CoreSig.SH_SHA256
    | SHA384 -> CoreSig.SH_SHA384

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

    CoreSig.sign (khash |> List.map cnvhash) kparams t

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

    CoreSig.verify (khash |> List.map cnvhash) kparams t s

(* ------------------------------------------------------------------------ *)
let gen (a:alg) : pkey * skey =
    let asig, ahash  = a in
    let (pkey, skey) =
        match asig with
        | SA_RSA -> CoreSig.gen CoreSig.SA_RSA
        | SA_DSA -> CoreSig.gen CoreSig.SA_DSA
        | _      -> failwith "unsupported / TODO"
    in
        ({ pkey = (pkey, ahash) }, { skey = (skey, ahash) })
