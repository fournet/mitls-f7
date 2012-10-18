module RSAPlain

open TLSInfo
open Bytes

type pms

val genPMS: SessionInfo -> TLSConstants.ProtocolVersion -> pms

val coerce: SessionInfo -> bytes -> pms
val leak: SessionInfo -> pms -> bytes