module HSK

open Bytes

type hint = string (* hostname CN *)
type cert = bytes  (* public part of a certificate *)

val for_signing : hint -> Sig.alg -> (cert * Sig.skey * Sig.vkey) option
val for_key_encryption : hint -> (cert * RSA.rsaskey * RSA.rsapkey) option
