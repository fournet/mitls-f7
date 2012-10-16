module Sig

open Bytes
open Algorithms

(* ------------------------------------------------------------------------ *)
type chash = hashAlg List
type alg   = sigAlg * chash

type text = bytes
type sigv = bytes 

(* ------------------------------------------------------------------------ *)
type skey
type pkey

val create_skey: chash -> CoreSig.sigskey -> skey
val create_vkey: chash -> CoreSig.sigpkey -> pkey

val repr_of_skey: skey -> CoreSig.sigskey * chash
val repr_of_pkey: pkey -> CoreSig.sigpkey * chash

val sigalg_of_skeyparams : CoreSig.sigskey -> sigAlg
val sigalg_of_pkeyparams : CoreSig.sigpkey -> sigAlg

(* ------------------------------------------------------------------------ *)
val gen    : alg -> pkey * skey
val sign   : alg -> skey -> text -> sigv
val verify : alg -> pkey -> text -> sigv -> bool
