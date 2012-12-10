module TLSPRF

open Bytes
open TLSConstants

(* Verify data *)
val ssl_verifyData : bytes -> bytes  -> bytes -> bytes
val tls_verifyData : bytes -> string -> bytes -> bytes
val tls12VerifyData: cipherSuite -> bytes -> string -> bytes -> bytes

(* PRF *)
val prf: ProtocolVersion -> cipherSuite -> bytes -> string -> bytes -> int -> bytes

(* SSL-specific certificate verify *)
val ssl_certificate_verify: bytes -> bytes -> hashAlg -> bytes