module TLSPRF

open Bytes
open TLSConstants
open TLSInfo

val verifyData: prfAlg -> bytes -> Role -> bytes -> bytes 
val extract: kefAlg -> bytes -> bytes -> int -> bytes
val kdf: prfAlg -> bytes -> bytes -> int -> bytes

(* SSL-specific certificate verify *)

val ssl_verifyCertificate: hashAlg -> bytes -> bytes -> bytes