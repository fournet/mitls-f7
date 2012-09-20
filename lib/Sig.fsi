module Sig

open Bytes
open Algorithms

(* ------------------------------------------------------------------------ *)
type sigAlg = 
  | SA_RSA
  | SA_DSA 
  | SA_ECDSA
  
type alg = sigAlg * hashAlg

type text = bytes
type sigv = bytes 

(* ------------------------------------------------------------------------ *)
type skey
type vkey

val create_skey: hashAlg -> skeyparams -> skey
val create_vkey: hashAlg -> pkeyparams -> vkey

(* ------------------------------------------------------------------------ *)
val gen    : alg -> vkey * skey
val sign   : alg -> skey -> text -> sigv
val verify : alg -> vkey -> text -> sigv -> bool
