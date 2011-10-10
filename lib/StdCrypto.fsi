module StdCrypto

open Data
open Error_handling
open Algorithms

(* For PRF *)

val hash: hashAlg -> bytes -> bytes Result

(* For authenticated encryption *)

type macKey = bytes
type symKey = bytes

val sslKeyedHash: hashAlg -> macKey -> bytes -> bytes Result
val sslKeyedHashVerify: hashAlg -> macKey -> bytes -> bytes -> unit Result

val hmac: hashAlg -> macKey -> bytes -> bytes Result
val hmacVerify: hashAlg -> macKey -> bytes -> bytes -> unit Result

val symEncrypt: cipherAlg -> symKey -> bytes -> bytes -> bytes Result
val symDecrypt: cipherAlg -> symKey -> bytes -> bytes -> bytes Result

(* Possibly, we might add some AES_GCM algorithms *)

(* FIXME: we need some RSA asymmetric enc/dec and DH for key exchange.
   Keeping it raw by now *)
type asymKey

val rsaEncrypt: asymKey -> bytes -> bytes Result
val rsaDecrypt: asymKey -> bytes -> bytes Result

(* FIXME: other raw stuff for handshake *)
val mkRandom: int -> bytes