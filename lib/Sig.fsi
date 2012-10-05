module Sig

open Bytes
open Algorithms

(* ------------------------------------------------------------------------ *)
type chash = CHash of hashAlg List
type alg   = sigAlg * chash

type text = bytes
type sigv = bytes 

(* ------------------------------------------------------------------------ *)
type skey
type vkey

val create_skey: chash -> skeyparams -> skey
val create_vkey: chash -> pkeyparams -> vkey

(* ------------------------------------------------------------------------ *)
val gen    : alg -> vkey * skey
val sign   : alg -> skey -> text -> sigv
val verify : alg -> vkey -> text -> sigv -> bool
