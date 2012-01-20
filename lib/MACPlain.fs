module MACPlain

open Bytes
open Algorithms
open CipherSuites
open TLSInfo

type MACPlain = {p:bytes}

let MACPlain ki tlen ad f =
    let fB = TLSFragment.AEADRepr ki tlen ad f
    let fLen = bytes_of_int 2 (length fB) in
    let fullData = ad @| fLen in 
    {p = fullData @| fB}

let reprMACPlain (ki:KeyInfo) p = p.p

type MACed = {m:bytes}
let MACed (ki:KeyInfo) b = {m=b}
let reprMACed (ki:KeyInfo) m = m.m


let parseNoPad (ki:KeyInfo) (n:int) ad plain =
    // assert length plain = n
    let maclen = 
        let cs = ki.sinfo.cipher_suite in
        macSize (macAlg_of_ciphersuite cs) in
    let macStart = n - maclen
    if macStart < 0 then
        (* FIXME: is this safe?
           I (AP) think so because our locally computed mac will have some different length.
           Also timing is not an issue, because the attacker can guess the check should fail anyway. *)
    //CF: no, the MAC has the wrong size; I'd rather have a static precondition on the length of c.
        let aeadF = TLSFragment.AEADFragment ki n ad plain
        let tag = MACed ki [||]
        (aeadF,tag)
    else
        let (frag,mac) = split plain macStart in
        let aeadF = TLSFragment.AEADFragment ki n ad frag
        let tag = MACed ki mac
        (aeadF,tag)