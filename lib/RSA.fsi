module RSA

open TLSInfo
open Bytes
open TLSConstants


val encrypt: RSAKey.pk -> ProtocolVersion -> CRE.rsapms -> bytes 

// This is not just plain RSA_PKCS1 decryption.
// We put in place timing attack countermeasures.
// See RFC 5246, section 7.4.7.1
val decrypt: RSAKey.sk -> SessionInfo -> ProtocolVersion -> bool -> bytes -> CRE.rsapms
