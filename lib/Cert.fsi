module Cert

open Bytes
open Error

type hint = string (* hostname CN *)
type cert = bytes  (* public part of a certificate *)

type certchain = cert list
type sign_cert = (certchain * Sig.alg * Sig.skey) option
type enc_cert  = (certchain * RSAKeys.sk) option

(* First argument (Sig.alg list) for both functions gives the allowed
 * signing alg. used for signing the key. For [for_signing] TLS1.2
 * allows the signing alg. used for the key to be different from the
 * signing alg. that can be used with that key.
 *)
val for_signing : Sig.alg list -> hint -> Sig.alg list -> sign_cert
val for_key_encryption : Sig.alg list -> hint -> enc_cert

val get_public_signing_key : cert -> Sig.alg -> Sig.pkey Result
val get_public_encryption_key : cert -> RSAKeys.pk Result

val is_for_signing : cert -> bool
val is_for_key_encryption : cert -> bool

val get_chain_public_signing_key : certchain -> Sig.alg -> Sig.pkey Result
val get_chain_public_encryption_key : certchain -> RSAKeys.pk Result

val is_chain_for_signing : certchain -> bool
val is_chain_for_key_encryption : certchain -> bool

val get_chain_key_algorithm : certchain -> TLSConstants.sigAlg option

val get_hint : certchain -> hint option

(* First argument (Sig.alg list) gives the allowed signing alg. used for
 * signing the keys of the chain.
 *)
val validate_cert_chain : Sig.alg list -> certchain -> bool
