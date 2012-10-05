module Cert

open Bytes
open Error

type hint = string (* hostname CN *)
type cert = bytes  (* public part of a certificate *)

type certchain = cert list
type sign_cert = (certchain * Sig.skey) option

val for_signing : hint -> Sig.alg list -> sign_cert
val for_key_encryption : hint -> (certchain * RSA.sk) option

val get_public_signing_key : cert -> Sig.alg -> Sig.vkey Result
val get_public_encryption_key : cert -> RSA.pk Result

val is_for_signing : cert -> bool
val is_for_key_encryption : cert -> bool

val get_chain_public_signing_key : certchain -> Sig.alg -> Sig.vkey Result
val get_chain_public_encryption_key : certchain -> RSA.pk Result

val is_chain_for_signing : certchain -> bool
val is_chain_for_key_encryption : certchain -> bool

(* WARN: does not checked that the CA is trusted *)
val validate_cert_chain : certchain -> bool
