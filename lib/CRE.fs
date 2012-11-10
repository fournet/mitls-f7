module CRE

open Bytes
open TLSConstants
open TLSInfo
open TLSPRF

type rsarepr = bytes
type rsapms = {rsapms: rsarepr}

#if ideal
let honest_log = ref []
let honest pms =
    match assoc !honest_log pms with
        Some -> true
        None -> false
let log = ref []
#endif

let genRSA (pk:RSAKeys.pk) (vc:TLSConstants.ProtocolVersion) : rsapms = 
    let verBytes = TLSConstants.versionBytes vc in
    let rnd = Nonce.mkRandom 46 in
    let pms = verBytes @| rnd in
    {rsapms = pms}

let coerceRSA (pk:RSAKeys.pk) (pv:ProtocolVersion) b = {rsapms = b}
let leakRSA (pk:RSAKeys.pk) (pv:ProtocolVersion) pms = pms.rsapms

type dhpms = {dhpms: DHGroup.elt}

let sampleDH p g (gx:DHGroup.elt) (gy:DHGroup.elt) = 
    let gz = DHGroup.genElement p g in
    let pms = {dhpms = gz}
    #if ideal
    honest_log := pms::!honest_log
    #endif
    pms

let coerceDH (p:DHGroup.p) (g:DHGroup.g) (gx:DHGroup.elt) (gy:DHGroup.elt) b = {dhpms = b}

// internal
let prfMS sinfo pmsBytes: PRF.masterSecret =
    let pv = sinfo.protocol_version in
    let cs = sinfo.cipher_suite in
    let data = sinfo.init_crand @| sinfo.init_srand in
    let res = generic_prf pv cs pmsBytes tls_master_secret data 48 in
    PRF.coerce sinfo res

let prfSmoothRSA si (pv:ProtocolVersion) pms = prfMS si pms.rsapms
let prfSmoothDHE si (p:DHGroup.p) (g:DHGroup.g) (gx:DHGroup.elt) (gy:DHGroup.elt) pms = 
    #if ideal
    if not(corrupt pms)
    then match assoc !log pms with
             Some(ms) -> ms
             None -> 
                 let ms=PRF.sampleMS si 
                 log := (prf,ms)::log
                 ms 
    else prfMS si pms.dhpms
    #else
    prfMS si pms.dhpms
    #endif


