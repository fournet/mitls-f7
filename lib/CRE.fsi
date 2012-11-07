module CRE

open Bytes
open TLSConstants
open TLSInfo
open Error

type rsarepr = bytes
type rsapms

val genRSA: RSAKeys.pk -> TLSConstants.ProtocolVersion -> rsapms

val coerceRSA: RSAKeys.pk -> ProtocolVersion -> rsarepr -> rsapms
val leakRSA: RSAKeys.pk -> ProtocolVersion -> rsapms -> rsarepr

type dhpms

val sampleDH: DHGroup.p -> DHGroup.g -> DHGroup.elt -> DHGroup.elt -> dhpms

val coerceDH: DHGroup.p -> DHGroup.g -> DHGroup.elt -> DHGroup.elt -> DHGroup.elt -> dhpms

val prfSmoothRSA: SessionInfo -> ProtocolVersion -> rsapms -> PRF.masterSecret
val prfSmoothDHE: SessionInfo -> DHGroup.p -> DHGroup.g -> DHGroup.elt -> DHGroup.elt -> dhpms -> PRF.masterSecret 

(* Used when generating key material from the MS. 
   The result must still be split into the various keys.
   Of course this method can do the splitting internally and return a record/pair *)



// SSL 3 specific encoding function for certificate verify

