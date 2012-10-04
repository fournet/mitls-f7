module Cert

open Bytes
open Error

type hint = string (* hostname CN *)
type cert = bytes  (* public part of a certificate *)

val for_signing : hint -> Sig.alg list -> (cert * cert list * Sig.skey) option
val for_key_encryption : hint -> (cert * cert list * RSA.sk) option

val get_public_signing_key : cert -> Sig.alg -> Sig.vkey Result
val get_public_encryption_key : cert -> RSA.pk Result

val is_for_signing : cert -> bool
val is_for_key_encryption : cert -> bool

val validate_chain : cert -> cert list -> bool (* TODO *)
