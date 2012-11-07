module PRF

open Bytes
open TLSInfo

type repr = bytes
type masterSecret

val keyGen: ConnectionInfo -> masterSecret -> StatefulAEAD.writer * StatefulAEAD.reader

val makeVerifyData:  SessionInfo -> Role -> masterSecret -> bytes -> bytes 
val checkVerifyData: SessionInfo -> Role -> masterSecret -> bytes -> bytes -> bool

val ssl_certificate_verify: SessionInfo -> masterSecret -> TLSConstants.sigAlg -> bytes -> bytes

val coerce: SessionInfo -> repr -> masterSecret