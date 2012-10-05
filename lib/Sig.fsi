module Sig

open Bytes
open Algorithms

(* ------------------------------------------------------------------------ *)
type alg = sigAlg * (hashAlg list)

type text = bytes
type sigv = bytes 

(* ------------------------------------------------------------------------ *)
type skey
type vkey

val create_skey: alg -> skeyparams -> skey
val create_vkey: alg -> pkeyparams -> vkey

(* ------------------------------------------------------------------------ *)
val gen    : alg -> vkey * skey
val sign   : alg -> skey -> text -> sigv
val verify : alg -> vkey -> text -> sigv -> bool
