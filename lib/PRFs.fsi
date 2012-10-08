module PRFs

open Bytes
open Formats
open TLSInfo
open RSA
open Error

(* see .fs7 for comments *) 

type repr = bytes
type masterSecret 

val prfSmoothRSA: SessionInfo -> RSAPlain.pms -> masterSecret
val prfSmoothDH:  SessionInfo -> DH.p -> DH.elt -> DH.elt -> DH.elt -> DH.pms -> masterSecret 

(* Used when generating key material from the MS. 
   The result must still be split into the various keys.
   Of course this method can do the splitting internally and return a record/pair *)

val keyGen: ConnectionInfo -> masterSecret -> StatefulAEAD.writer * StatefulAEAD.reader

val makeTimestamp: unit -> int

val makeVerifyData:  SessionInfo -> Role -> masterSecret -> bytes -> bytes 
val checkVerifyData: SessionInfo -> Role -> masterSecret -> bytes -> bytes -> bool

// Maybe this is the wrong place? Better in Sig? Now placed here since it accesses MS bytes.
val ssl_certificate_verify: SessionInfo -> masterSecret -> Sig.alg -> Sig.skey -> Sig.text -> Sig.sigv
val ssl_certificate_verify_check: SessionInfo -> masterSecret -> Sig.alg -> Sig.vkey -> Sig.text -> Sig.sigv -> bool