module RSA

open TLSInfo
open Bytes
open TLSConstants

val encrypt: RSAKey.pk -> ProtocolVersion -> CRE.rsapms -> bytes 
val decrypt: RSAKey.sk -> SessionInfo -> ProtocolVersion -> bool -> bytes -> CRE.rsapms
