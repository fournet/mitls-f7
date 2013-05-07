module PRF

open Bytes
open TLSConstants
open TLSInfo

val prfAlg: SessionInfo -> prfAlg  
 
type msIndex =  
  pmsId * 
  csrands *                                          
  prfAlg  

val msi: SessionInfo -> msIndex
   
#if ideal
val safeMS_msIndex: msIndex -> bool  
#endif

type repr = bytes
type ms
type masterSecret = ms

#if ideal
val sample: SessionInfo -> PMS.pms -> masterSecret
#endif

//#begin-coerce
val coerce: SessionInfo -> PMS.pms -> repr -> masterSecret
//#end-coerce

val keyCommit: csrands -> aeAlg -> unit
val keyGenClient: ConnectionInfo -> masterSecret -> StatefulLHAE.writer * StatefulLHAE.reader
val keyGenServer: ConnectionInfo -> masterSecret -> StatefulLHAE.writer * StatefulLHAE.reader

val makeVerifyData:  SessionInfo -> masterSecret -> Role -> bytes -> bytes 
val checkVerifyData: SessionInfo -> masterSecret -> Role -> bytes -> bytes -> bool

val ssl_certificate_verify: SessionInfo -> masterSecret -> TLSConstants.sigAlg -> bytes -> bytes

