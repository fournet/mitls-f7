module Cert

open Bytes
open Error
open TLSError
open UntrustedCert

type hint = UntrustedCert.hint 
type cert = UntrustedCert.cert  

type chain = UntrustedCert.chain
type sign_cert = (chain * Sig.alg * Sig.skey) option
type enc_cert  = (chain * RSAKey.sk) option

val for_signing : Sig.alg list -> hint -> Sig.alg list -> sign_cert
val for_key_encryption : Sig.alg list -> hint -> enc_cert

val get_public_signing_key : cert -> Sig.alg -> Sig.pkey Result
val get_public_encryption_key : cert -> RSAKey.pk Result

val get_chain_public_signing_key : chain -> Sig.alg -> Sig.pkey Result
val get_chain_public_encryption_key : chain -> RSAKey.pk Result

val is_chain_for_signing : chain -> bool
val is_chain_for_key_encryption : chain -> bool

val get_hint : chain -> hint option
val validate_cert_chain : Sig.alg list -> chain -> bool
val parseCertificateList: bytes -> chain -> chain Result
val certificateListBytes: chain -> bytes