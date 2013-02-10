module PRF

open Bytes
open TLSInfo

type repr = bytes
type masterSecret

#if ideal
val sample: SessionInfo -> masterSecret
#endif

val keyGen: ConnectionInfo -> masterSecret -> StatefulLHAE.writer * StatefulLHAE.reader

val makeVerifyData:  epoch -> Role -> masterSecret -> bytes -> bytes 
val checkVerifyData: epoch -> Role -> masterSecret -> bytes -> bytes -> bool

val ssl_certificate_verify: SessionInfo -> masterSecret -> TLSConstants.sigAlg -> bytes -> bytes

//#begin-coerce
val coerce: SessionInfo -> repr -> masterSecret //#end-coerce