﻿module MAC

open Bytes
open TLSConstants

open TLSInfo
open Error

type text = bytes
type tag = bytes

type key = {k:bytes}

#if ideal 
let log=ref []
#endif

let Mac ki key data =
    let si = epochSI(ki) in
    let pv = si.protocol_version in
    let a = macAlg_of_ciphersuite si.cipher_suite pv in
    let tag = HMAC.MAC a key.k data in
    #if ideal
    // We log every authenticated texts, with their index and resulting tag
    log := (ki, data, tag)::!log;
    #endif
    tag

let Verify ki key data tag =
    let si = epochSI(ki) in
    let pv = si.protocol_version in
    let a = macAlg_of_ciphersuite si.cipher_suite pv in
    HMAC.MACVERIFY a key.k data tag
    #if ideal
    // At safe indexes, we use the log to detect and correct verification errors
    && if MAC_safe ki
       then 
           exists (fun (ki', data', _) -> ki'=ki && data'= data) !log
       else 
           true  
    #endif

let GEN (ki) =
    let si = epochSI(ki) in
    {k= Nonce.mkRandom (macKeySize (macAlg_of_ciphersuite si.cipher_suite si.protocol_version))}
let COERCE (ki:epoch) k = {k=k}
let LEAK (ki:epoch) {k=k} = k
