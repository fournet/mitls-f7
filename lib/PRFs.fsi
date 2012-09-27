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

val keyGen: ConnectionInfo -> masterSecret -> StatefulAEAD.state * StatefulAEAD.state

val makeTimestamp: unit -> int

val prfVerifyData: SessionInfo -> Role -> masterSecret -> bytes -> bytes 

