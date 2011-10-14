module OtherCrypto

(* Contains crypto functions not yet ported to the computational model. *)
(* One day this module will disappear and all the code will only use
   computationally-friendly modules *)
open Data
open Error_handling

(* RSA asymmetric enc/dec and DH for key exchange. *)
type asymKey

val rsaEncrypt: asymKey -> bytes -> bytes Result
val rsaDecrypt: asymKey -> bytes -> bytes Result

val rsa_skey: str -> asymKey
val rsa_pkey_bytes: bytes -> asymKey

(* Other raw stuff for handshake *)
val mkRandom: int -> bytes