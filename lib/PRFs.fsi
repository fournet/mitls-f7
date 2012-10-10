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
val prfSmoothDHE: SessionInfo -> DHE.pms -> masterSecret 

(* Used when generating key material from the MS. 
   The result must still be split into the various keys.
   Of course this method can do the splitting internally and return a record/pair *)

val keyGen: ConnectionInfo -> masterSecret -> StatefulAEAD.writer * StatefulAEAD.reader

val makeTimestamp: unit -> int

val makeVerifyData:  SessionInfo -> Role -> masterSecret -> bytes -> bytes 
val checkVerifyData: SessionInfo -> Role -> masterSecret -> bytes -> bytes -> bool

// SSL 3 specific encoding function for certificate verify
val ssl_certificate_verify: SessionInfo -> masterSecret -> Sig.alg -> bytes -> bytes