module CryptoTLS

open Data
open Error_handling
open Crypto

val symkey: bytes -> key
val symkeytobytes: key -> bytes

val hmacsha1: key -> bytes -> bytes Result
val hmacmd5: key -> bytes -> bytes Result

val hmacsha1Verify: key -> bytes -> bytes -> unit Result
val hmacmd5Verify: key -> bytes -> bytes -> unit Result

val keyedHash: (bytes -> bytes Result) -> bytes -> bytes -> key -> bytes -> bytes Result
val keyedHashVerify: (bytes -> bytes Result) -> bytes -> bytes -> key -> bytes -> bytes -> unit Result

val md5: bytes -> bytes Result
val sha1: bytes -> bytes Result

val des_encrypt_wiv: key -> bytes -> bytes -> bytes Result
val aes_encrypt_wiv: key -> bytes -> bytes -> bytes Result

val des_decrypt_wiv: key -> bytes -> bytes -> bytes Result
val aes_decrypt_wiv: key -> bytes -> bytes -> bytes Result