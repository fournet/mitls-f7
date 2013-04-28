module CRE

open Bytes
open TLSConstants
open TLSInfo
open Error
open PMS

val extractRSA: SessionInfo -> ProtocolVersion -> rsapms -> PRF.masterSecret
val extractDHE: SessionInfo -> DHGroup.p -> DHGroup.g -> DHGroup.elt -> DHGroup.elt -> dhpms -> PRF.masterSecret 

(* Used when generating key material from the MS. 
   The result must still be split into the various keys.
   Of course this method can do the splitting internally and return a record/pair *)



//TODO SSL 3 specific encoding function for certificate verify

