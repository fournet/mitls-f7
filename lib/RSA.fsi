module RSA

(* See RSA.f7 for information *)
open Bytes
open Error

type rsaskey
type rsapkey

val rsaEncrypt: rsapkey -> bytes -> bytes Result
val rsaDecrypt: rsaskey -> bytes -> bytes Result

val create_rsapkey : bytes * bytes -> rsapkey
val create_rsaskey : bytes * bytes -> rsaskey