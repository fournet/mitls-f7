module PRF

open Bytes
open TLSInfo

type prfAlg = 
  | PRF_TLS_1p2 of TLSConstants.macAlg 
  | PRF_TLS_1p01           
  | PRF_SSL3_nested        
  | PRF_SSL3_concat   

val prfAlgOf: SessionInfo -> prfAlg  
 
type msIndex =  
  PMS.pms * 
  csrands *                                          
  prfAlg  
   
val safeMS_msIndex: msIndex -> bool  

type repr = bytes
type ms
type masterSecret = ms

#if ideal
val sample: SessionInfo -> masterSecret
#endif

//#begin-coerce
val coerce: SessionInfo -> repr -> masterSecret
//#end-coerce

val keyGen: ConnectionInfo -> masterSecret -> StatefulLHAE.writer * StatefulLHAE.reader

val makeVerifyData:  SessionInfo -> masterSecret -> Role -> bytes -> bytes 
val checkVerifyData: SessionInfo -> masterSecret -> Role -> bytes -> bytes -> bool

val ssl_certificate_verify: SessionInfo -> masterSecret -> TLSConstants.sigAlg -> bytes -> bytes

