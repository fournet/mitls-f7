module Cert

open Bytes
open Error

type hint = string (* hostname CN *)
type cert = bytes  (* public part of a certificate *)

type certchain = cert list
type sign_cert = (certchain * Sig.alg * Sig.skey) option

(* First argument (Sig.alg list) for both functions gives the allowed
 * signing alg. used for signing the key. For [for_signing] TLS1.2
 * allows the signing alg. used for the key to be difference from the
 * signing alg. that can be used with that key.
 *)
val for_signing : Sig.alg list -> hint -> Sig.alg list -> sign_cert
val for_key_encryption : Sig.alg list -> hint -> (certchain * RSA.sk) option

val get_public_signing_key : cert -> Sig.alg -> Sig.vkey Result
val get_public_encryption_key : cert -> RSA.pk Result

val is_for_signing : cert -> bool
val is_for_key_encryption : cert -> bool

val get_chain_public_signing_key : certchain -> Sig.alg -> Sig.vkey Result
val get_chain_public_encryption_key : certchain -> RSA.pk Result

val is_chain_for_signing : certchain -> bool
val is_chain_for_key_encryption : certchain -> bool

val get_chain_key_algorithm : certchain -> Algorithms.sigAlg option

(* WARN: does not checked that the CA is trusted
 * First argument (Sig.alg list) gives the allowed signing alg. used for
 * signing the keys of the chain.
 *)
val validate_cert_chain : Sig.alg list -> certchain -> bool
