module CRE

open Bytes
open TLSConstants
open TLSInfo
open Error
open TLSError
open PMS

val extract: SessionInfo -> pms -> PRF.masterSecret

(* Used when generating key material from the MS. 
   The result must still be split into the various keys.
   Of course this method can do the splitting internally and return a record/pair *)

//TODO SSL 3 specific encoding function for certificate verify

