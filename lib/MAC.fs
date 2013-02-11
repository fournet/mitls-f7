module MAC

open Bytes
open TLSConstants

open TLSInfo
open Error

type text = bytes
type tag = bytes
type keyrepr = bytes
type key = 
  | KeyNoAuth of keyrepr
  | Key_a of MACa.key
 
// this ideal variant enables us to directly specify that MAC is ideal
// at safe indexes; we do not need that assumption anymore, as we 
// typecheck the code below against the usual INT-CMA interface:
// idealization occurs within each of their implementations.
#if false
type entry = epoch * text * tag
let log:entry list ref=ref []
let rec tmem (e:epoch) (t:text) (xs: entry list) = 
  match xs with
      [] -> false
    | (e',t',tag)::res when e = e' && t = t' -> true
    | (e',t',tag)::res -> tmem e t res
#endif

let Mac ki key data =
    let si = epochSI(ki) in
    let pv = si.protocol_version in
    let a = macAlg_of_ciphersuite si.cipher_suite pv in
    #if false
    let tag = 
    #endif
      match key with 
        | KeyNoAuth(k) -> HMAC.MAC a k data 
        | Key_a(k)     -> MACa.Mac ki k data 
    #if false
    // We log every authenticated texts, with their index and resulting tag
    log := (ki, data, tag)::!log;
    tag
    #endif

let Verify ki key data tag =
    let si = epochSI(ki) in
    let pv = si.protocol_version in
    let a = macAlg_of_ciphersuite si.cipher_suite pv in
    match key with 
    | Key_a(k)     -> MACa.Verify ki k data tag
    | KeyNoAuth(k) -> HMAC.MACVERIFY a k data tag
    #if false
    // At safe indexes, we use the log to detect and correct verification errors
    && if MAC_safe ki
       then 
           tmem ki data !log
       else 
           true  
    #endif

let GEN ki =
    let si = epochSI(ki) in
    let a = macAlg_of_ciphersuite si.cipher_suite si.protocol_version in
    #if ideal
    if MAC_safe ki then 
      match a with 
      | a when a = MACa.a -> Key_a(MACa.GEN ki)
      | a                 -> unreachable "only strong algorithms provide safety"
    else                   
    #endif
    KeyNoAuth(Nonce.mkRandom (macKeySize (a)))

let COERCE (ki:epoch) k = KeyNoAuth(k)  
let LEAK (ki:epoch) k = 
    match k with 
    | Key_a(k)     -> unreachable "since we have Auth"
    | KeyNoAuth(k) -> k
