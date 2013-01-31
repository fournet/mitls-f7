﻿module CRE

open Bytes
open TLSConstants
open TLSInfo
open TLSPRF

type rsarepr = bytes
type rsapms = {rsapms: rsarepr}
type dhpms = {dhpms: DHGroup.elt}

#if ideal
type pms = RSA_pms of rsapms | DHE_pms of dhpms

// We maintain two log:
// - a log of honest pms values
// - a log for looking up good ms values using their pms values values
// MK the first log is used in two idealization steps

let honest_log = ref []
let honest pms = exists (fun el -> el=pms) !honest_log

let corrupt pms = 
    not(honest pms)

let log = ref []
#endif

let genRSA (pk:RSAKey.pk) (vc:TLSConstants.ProtocolVersion) : rsapms = 
    let verBytes = TLSConstants.versionBytes vc in
    let rnd = Nonce.mkRandom 46 in
    let pms = verBytes @| rnd in
    let pms = {rsapms = pms}
    #if ideal
    if RSAKey.honest pk then honest_log := RSA_pms(pms)::!honest_log
    #endif
    pms

let coerceRSA (pk:RSAKey.pk) (pv:ProtocolVersion) b = {rsapms = b}
let leakRSA (pk:RSAKey.pk) (pv:ProtocolVersion) pms = pms.rsapms



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

(* MK assumption notes

We require prfMS to be a deterministic computational randomness extractor for both 
of the distributions generated by genRSA and sampleDH. It is sufficient for the following two 
distributions to be indistinguishable to establish using a standard hybrid argument
indistinguishability of any polynomial length sequence of the two distributions on the right 
from the same length sequence of PRF.sample.

PRF.sample si ~_C prfMS si genRSA pk vc //relate si and pk vc
PRF.sample si ~_C prfMS si sampleDH p g //relate si and p g

*)

let prfSmoothRSA si (pv:ProtocolVersion) pms = 
    #if ideal
    // MK this idealization relies on si being used only once with this function
    if not(corrupt (RSA_pms(pms)))
    then match tryFind (fun el -> fst el = RSA_pms(pms)) !log with
             Some(_,ms) -> ms
           | None -> 
                 let ms=PRF.sample si 
                 log := (RSA_pms(pms),ms)::!log
                 ms 
    else prfMS si pms.rsapms
    #else
    prfMS si pms.rsapms
    #endif

let prfSmoothDHE si (p:DHGroup.p) (g:DHGroup.g) (gx:DHGroup.elt) (gy:DHGroup.elt) (pms:dhpms) = 
    #if ideal
    // MK this idealization relies on si being used only once with this function
    if not(corrupt (DHE_pms(pms)))
    then match tryFind (fun el -> fst el = DHE_pms(pms)) !log  with
             Some(_,ms) -> ms
           | None -> 
                 let ms=PRF.sample si 
                 log := (DHE_pms(pms),ms)::!log;
                 ms 
    else prfMS si pms.dhpms
    #else
    prfMS si pms.dhpms
    #endif


