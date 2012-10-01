module RSAPlain

open TLSInfo
open Bytes

type pms

val genPMS: SessionInfo -> CipherSuites.ProtocolVersion -> pms

val coerce: SessionInfo -> bytes -> pms
val leak: SessionInfo -> pms -> bytes