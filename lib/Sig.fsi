module Sig

open Bytes
open Algorithms

(* ------------------------------------------------------------------------ *)
type sigAlg = 
  | SA_RSA
  | SA_DSA 
  | SA_ECDSA

type hashAlg =
  | MD5    // 1
  | SHA1   // 2
  | SHA224 // 3
  | SHA256 // 4
  | SHA384 // 5
  | SHA512 // 6
  
type alg = sigAlg * Algorithms.hashAlg

type text = bytes
type sigv = bytes 

(* ------------------------------------------------------------------------ *)
type skey
type vkey

(* ------------------------------------------------------------------------ *)
val gen    : alg -> vkey * skey
val sign   : alg -> skey -> text -> sigv
val verify : alg -> vkey -> text -> sigv -> bool
