module RSAEnc

open RSA
open TLSInfo
open RSAPlain
open Bytes
open CipherSuites

(* FOR DEBUGGING PURPOSES *)
val encrypt_pkcs1 : pk -> bytes -> bytes
val decrypt_pkcs1 : sk -> bytes -> bytes option

val encrypt: pk -> SessionInfo -> pms -> bytes 
// This is *not* plain RSA_PKCS1 decryption.
// We put in place all known timing attack countermeasures.
// See RFC 5246, section 7.4.7.1
val decrypt: sk -> SessionInfo -> ProtocolVersion -> bool -> bytes -> pms
