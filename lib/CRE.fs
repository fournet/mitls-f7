module CRE

open Bytes
open TLSConstants
open TLSInfo
open TLSPRF

type rsarepr = bytes
type rsapms = {rsapms: rsarepr}
type dhpms = {dhpms: DHGroup.elt}

#if ideal
type pms = RSA_pms of rsapms | DHE_pms of dhpms

let honest_log = ref []
let honest pms = exists (fun el -> el=pms) !honest_log

let corrupt pms = 
    not(honest pms)

let log = ref []
#endif

let genRSA (pk:RSAKeys.pk) (vc:TLSConstants.ProtocolVersion) : rsapms = 
    let verBytes = TLSConstants.versionBytes vc in
    let rnd = Nonce.mkRandom 46 in
    let pms = verBytes @| rnd in
    let pms = {rsapms = pms}
    #if ideal
    if RSAKeys.honest pk then honest_log := RSA_pms(pms)::!honest_log
    #endif
    pms

let coerceRSA (pk:RSAKeys.pk) (pv:ProtocolVersion) b = {rsapms = b}
let leakRSA (pk:RSAKeys.pk) (pv:ProtocolVersion) pms = pms.rsapms



let sampleDH p g (gx:DHGroup.elt) (gy:DHGroup.elt) = 
    let gz = DHGroup.genElement p g in
    let pms = {dhpms = gz}
    #if ideal
    honest_log := DHE_pms(pms)::!honest_log
    #endif
    pms

let coerceDH (p:DHGroup.p) (g:DHGroup.g) (gx:DHGroup.elt) (gy:DHGroup.elt) b = {dhpms = b} 

// internal
let prfMS sinfo pmsBytes: PRF.masterSecret =
    let pv = sinfo.protocol_version in
    let cs = sinfo.cipher_suite in
    let data = sinfo.init_crand @| sinfo.init_srand in
    let res = prf pv cs pmsBytes tls_master_secret data 48 in
    PRF.coerce sinfo res

let prfSmoothRSA si (pv:ProtocolVersion) pms = 
    #if ideal
    if not(corrupt (RSA_pms(pms)))
    then match tryFind (fun el -> fst el = RSA_pms(pms)) !log with
             Some(_,ms) -> ms
           | None -> 
                 let ms=PRF.sampleMS si 
                 log := (RSA_pms(pms),ms)::!log
                 ms 
    else prfMS si pms.rsapms
    #else
    prfMS si pms.rsapms
    #endif

let prfSmoothDHE si (p:DHGroup.p) (g:DHGroup.g) (gx:DHGroup.elt) (gy:DHGroup.elt) (pms:dhpms) = 
    #if ideal
    if not(corrupt (DHE_pms(pms)))
    then match tryFind (fun el -> fst el = DHE_pms(pms)) !log  with
             Some(_,ms) -> ms
           | None -> 
                 let ms=PRF.sampleMS si 
                 log := (DHE_pms(pms),ms)::!log;
                 ms 
    else prfMS si pms.dhpms
    #else
    prfMS si pms.dhpms
    #endif


