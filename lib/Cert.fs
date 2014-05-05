module Cert

(* ------------------------------------------------------------------------ *)

open Bytes
open TLSConstants
open Error
open TLSError
open UntrustedCert
open CoreSig
open Sig

type chain = UntrustedCert.chain
type hint = UntrustedCert.hint
type cert = UntrustedCert.cert 

type sign_cert = (chain * Sig.alg * Sig.skey) option
type enc_cert  = (chain * RSAKey.sk) option

(* ------------------------------------------------------------------------ *)

#if verify
let forall (test: (X509Certificate2 -> bool)) (chain : X509Certificate2 list) : bool = failwith "for specification purposes only, unverified" 
#else
let forall (test: (X509Certificate2 -> bool)) (chain : X509Certificate2 list) : bool = Seq.forall test chain
#endif


let for_signing (sigkeyalgs : Sig.alg list) (h : hint) (algs : Sig.alg list) =
    match (find_sigcert_and_alg sigkeyalgs h algs) with 
    | Some(x509, (siga, hasha)) ->
        let alg = (siga, hasha)          
        match x509_to_secret_key x509, x509_to_public_key x509 with
        | Some skey, Some pkey ->
            let chain = x509_chain x509 in

            if forall (x509_check_key_sig_alg_one sigkeyalgs) chain then
                let pk = create_pkey alg pkey
                #if ideal
                if honest alg pk then
                    None //loading of honest keys not implemented yet.
                else
                    let sk = coerce alg pk skey
                    Some (x509list_to_chain chain, alg, sk)
                #else
                Some (x509list_to_chain chain, alg, Sig.coerce alg pk skey)
                #endif
            else
                None
        | None, _ -> None
        | _, None -> None
    | None -> None

(* ------------------------------------------------------------------------ *)



let for_key_encryption (sigkeyalgs : Sig.alg list) (h : hint) =
            match (find_enccert sigkeyalgs h) with 
            | Some(x509) ->                     
                match x509_to_secret_key x509, x509_to_public_key x509 with
                | Some (CoreSig.SK_RSA(sm, se)), Some(CoreSig.PK_RSA(pm,pe)) ->
                    let chain = x509_chain x509 in

                    if forall (x509_check_key_sig_alg_one sigkeyalgs) chain then
                        let pk = (RSAKey.create_rsapkey (pm,pe))
                        Some (x509list_to_chain chain, 
                              RSAKey.coerce pk (CoreACiphers.RSASKey(sm, se)))
                    else
                        None
                | _,_ -> None
            | None -> None

(* ------------------------------------------------------------------------ *)
let get_public_signing_key (c : cert) ((siga, _) as a : Sig.alg) : Sig.pkey Result =
    match cert_to_x509 c with 
    | Some(x509) -> 
            if x509_is_for_signing x509 then
                match siga, x509_to_public_key x509 with
                | SA_RSA, Some (CoreSig.PK_RSA (sm, se) as k) -> Correct (Sig.create_pkey a k)
                | SA_DSA, Some (CoreSig.PK_DSA (y, p  ) as k) -> Correct (Sig.create_pkey a k)
                | _ -> Error(AD_unsupported_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate uses unknown signature algorithm or key")
            else
                Error(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate is not for signing")
    | None -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let get_public_encryption_key (c : cert) : RSAKey.pk Result =
    match cert_to_x509 c with 
    | Some(x509) -> 
            if x509_is_for_key_encryption x509 then
                match x509_to_public_key x509 with
                | Some (CoreSig.PK_RSA(pm, pe)) -> Correct (RSAKey.create_rsapkey (pm, pe))
                | _ -> Error(AD_unsupported_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate uses unknown key")
            else
                Error(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ "Certificate is not for key encipherment")
    | None -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

(* ------------------------------------------------------------------------ *)
let get_chain_public_signing_key (chain : chain) a =
    match chain with
    | []     -> Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "This is likely a bug, please report it")
    | c :: _ -> get_public_signing_key c a

let get_chain_public_encryption_key (chain : chain) =
    match chain with
    | []     -> Error(AD_internal_error, perror __SOURCE_FILE__ __LINE__ "This is likely a bug, please report it")
    | c :: _ -> get_public_encryption_key c

(* ------------------------------------------------------------------------ *)



let validate_cert_chain (sigkeyalgs : Sig.alg list) (chain : chain) =
    match chain with
    | []           -> false
    | c :: issuers ->
        match cert_to_x509 c with 
        | Some(x509) ->  
            validate_x509_chain sigkeyalgs x509 issuers  
        | None ->
            false

(* ------------------------------------------------------------------------ *)
let get_hint (chain : chain) =
    match chain_to_x509list chain with
    | Some x509list ->    
        match x509list with
        | []     -> None
        | c :: _ -> Some (get_name_info c) (* FIXME *)
    | None -> None

(* ------------------------------------------------------------------------ *)
let is_chain_for_signing (chain : chain) =
    match chain with [] -> false| c :: _ -> is_for_signing c

let is_chain_for_key_encryption (chain : chain) =
    match chain with [] -> false| c :: _ -> is_for_key_encryption c


(* ---- TLS-specific encoding ---- *)
let consCertificateBytes c a =
    let cert = vlbytes 3 c in
    cert @| a

let certificateListBytes certs =
    let unfolded = List.foldBack consCertificateBytes certs empty_bytes in
    vlbytes 3 unfolded

let rec parseCertificateList toProcess list =
    if equalBytes toProcess empty_bytes then
        correct(list)
    else
        if length toProcess >= 3 then
            match vlsplit 3 toProcess with
            | Error(x,y) -> Error(AD_bad_certificate_fatal, perror __SOURCE_FILE__ __LINE__ y)
            | Correct (res) ->
                let (nextCert,toProcess) = res in
                let list = list @ [nextCert] in
                parseCertificateList toProcess list
        else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
