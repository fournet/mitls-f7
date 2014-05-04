module PMS

open Bytes
open TLSConstants
open Error
open TLSError
open DHGroup

//CF some of those types are private to PMS & KEF

type rsarepr = bytes
type rsaseed = {seed: rsarepr}
type rsapms = 
#if ideal 
  | IdealRSAPMS of rsaseed 
#endif
  | ConcreteRSAPMS of rsarepr

type dhrepr = bytes
type dhseed = {seed: dhrepr}

type dhpms = 
#if ideal 
  | IdealDHPMS of dhseed 
#endif
  | ConcreteDHPMS of dhrepr

#if ideal
type predicates = EncryptedRSAPMS of RSAKey.pk * ProtocolVersion * rsapms * bytes
val honestRSAPMS: RSAKey.pk -> TLSConstants.ProtocolVersion -> rsapms -> bool
#endif

val genRSA: RSAKey.pk -> TLSConstants.ProtocolVersion -> rsapms

val coerceRSA: RSAKey.pk -> ProtocolVersion -> rsarepr -> rsapms
val leakRSA: RSAKey.pk -> ProtocolVersion -> rsapms -> rsarepr

#if ideal
val honestDHPMS: p -> g -> elt -> elt -> dhpms -> bool 
#endif

val sampleDH: DHGroup.p -> DHGroup.g -> DHGroup.elt -> DHGroup.elt -> dhpms

val coerceDH: DHGroup.p -> DHGroup.g -> DHGroup.elt -> DHGroup.elt -> DHGroup.elt -> dhpms


(* Used when generating key material from the MS. 
   The result must still be split into the various keys.
   Of course this method can do the splitting internally and return a record/pair *)



//TODO SSL 3 specific encoding function for certificate verify

type pms = 
  | RSAPMS of RSAKey.pk * ProtocolVersion * rsapms
  | DHPMS of p * g * elt * elt * dhpms