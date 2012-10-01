module RSAEnc

open RSA
open TLSInfo
open RSAPlain
open Bytes
open CipherSuites

val encrypt: pk -> SessionInfo -> pms -> bytes 
// Asymmetric name. This is *not* plain RSA decryption.
// We put in place all known timing attack countermeasures.
// See RFC 5246, section 7.4.7.1
val decrypt_PMS: dk -> SessionInfo -> ProtocolVersion -> bool -> bytes -> pms