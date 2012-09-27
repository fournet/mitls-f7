module RSA

// See comments in RSA.f7

open Bytes
open Error

// breaking type abstraction only for RSAEnc.fs
type dk = RSASKey of bytes * bytes
type pk = RSAPKey of bytes * bytes

val create_rsapkey : bytes * bytes -> pk
val create_rsaskey : bytes * bytes -> dk