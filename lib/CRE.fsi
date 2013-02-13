module CRE

open Bytes
open TLSConstants
open TLSInfo
open Error

type rsarepr = bytes
type rsapms
type dhpms

#if ideal
// MK use TLSInfo.pmsData instead?
type pms = RSA_pms of rsapms | DHE_pms of dhpms
val corrupt: pms -> bool
#endif

val genRSA: RSAKey.pk -> TLSConstants.ProtocolVersion -> rsapms

val coerceRSA: RSAKey.pk -> ProtocolVersion -> rsarepr -> rsapms
val leakRSA: RSAKey.pk -> ProtocolVersion -> rsapms -> rsarepr

val sampleDH: DHGroup.p -> DHGroup.g -> DHGroup.elt -> DHGroup.elt -> dhpms

val coerceDH: DHGroup.p -> DHGroup.g -> DHGroup.elt -> DHGroup.elt -> DHGroup.elt -> dhpms

val prfSmoothRSA: SessionInfo -> ProtocolVersion -> rsapms -> PRF.masterSecret
val prfSmoothDHE: SessionInfo -> DHGroup.p -> DHGroup.g -> DHGroup.elt -> DHGroup.elt -> dhpms -> PRF.masterSecret 

(* Used when generating key material from the MS. 
   The result must still be split into the various keys.
   Of course this method can do the splitting internally and return a record/pair *)



//TODO SSL 3 specific encoding function for certificate verify

