module RSAEnc

open RSA
open TLSInfo
open RSAPlain
open Bytes

val encrypt: pk -> SessionInfo -> pms -> bytes 
val decrypt: dk -> SessionInfo -> bytes -> pms