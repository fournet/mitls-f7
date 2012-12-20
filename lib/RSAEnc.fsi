module RSAEnc

open TLSInfo
open Bytes
open TLSConstants


val encrypt: RSAKeys.pk -> ProtocolVersion -> CRE.rsapms -> bytes 

// This is *not* plain RSA_PKCS1 decryption.
// We put in place all known timing attack countermeasures.
// See RFC 5246, section 7.4.7.1
val decrypt: RSAKeys.sk -> SessionInfo -> ProtocolVersion -> bool -> bytes -> CRE.rsapms
