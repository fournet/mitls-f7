module RSAEnc

open RSA
open TLSInfo
open RSAPlain
open Bytes
open CipherSuites

val encrypt: pk -> SessionInfo -> pms -> bytes 
// This is *not* plain RSA_PKCS1 decryption.
// We put in place all known timing attack countermeasures.
// See RFC 5246, section 7.4.7.1
val decrypt: sk -> SessionInfo -> ProtocolVersion -> bool -> bytes -> pms
