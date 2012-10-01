module Cert

open Bytes
open Error

type hint = string (* hostname CN *)
type cert = bytes  (* public part of a certificate *)

type certType =
    | RSA_sign
    | DSA_sign
    | RSA_fixed_dh
    | DSA_fixed_dh

val certTypeBytes: certType -> bytes
val parseCertType: bytes -> certType Result

val for_signing : hint -> Sig.alg -> (cert list * Sig.skey * Sig.vkey) option
val for_key_encryption : hint -> (cert list * RSA.dk * RSA.pk) option

val is_for_signing: cert list -> bool
val is_for_key_encryption: cert list -> bool