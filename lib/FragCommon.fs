module FragCommon

// This module is obsolete. It should be replaced by DataStream,
// and DataStream used by all upper protocols

open Bytes
open TLSInfo
open Algorithms
open CipherSuites

type tlen = int

(* generate the minimal padding for payload len, in 1..blocksize *)
// We need a typable version; not so hard (but we may need axioms on arrays)
// by convention, all paddings include their length byte. 
// the spec is that 
// len + padLength % bs = 0 /\ padLength in 1..256
let padLength sinfo len =
    let alg = encAlg_of_ciphersuite sinfo.cipher_suite in
    let bs = blockSize alg in
    let overflow = (len + 1) % bs // at least one extra byte of padding
    if overflow = 0 then 1 else 1 + bs - overflow 
    (* Always use fixed padding size *)
    (* earlier variants used random padding: 
    match ki.sinfo.protocol_version with
    | SSL_3p0 ->
        (* At most one bs. See sec 5.2.3.2 of SSL 3 draft *)
        min_padlen
    | v when v >= TLS_1p0 ->
        let rand = bs * (((int (OtherCrypto.mkRandom 1).[0]) - min_padlen) / bs) in 
        min_padlen + rand
    | _ -> unexpectedError "[compute_pad] invoked on wrong protocol version"
    *)

// let cipherLength sinfo plainLen =
//   let l = 
//     plainLen + 
//     let cs = sinfo.cipher_suite in
//     if isNullCipherSuite cs then 0 else 
//         let macLen = macSize (macAlg_of_ciphersuite cs) in
//         macLen + 
//         if isOnlyMACCipherSuite cs then 0 else padLength sinfo (plainLen + macLen) 
//         // TODO: add support for GCM, now we only support MtE
//   l

let cipherLength sinfo plainLen =
    let cs = sinfo.cipher_suite in
    if isNullCipherSuite cs then
        plainLen
    else if isOnlyMACCipherSuite cs then
        let macLen = macSize (macAlg_of_ciphersuite cs) in
        let res = plainLen + macLen in
        res
    else
        let ivL =
            match sinfo.protocol_version with
            | SSL_3p0 | TLS_1p0 -> 0
            | TLS_1p1 | TLS_1p2 ->
                let encAlg = encAlg_of_ciphersuite cs in
                ivSize encAlg
        let macLen = macSize (macAlg_of_ciphersuite cs) in
        let prePad = plainLen + macLen in
        let padLen = padLength sinfo prePad in
        ivL + prePad + padLen

let splitInFrag ki b =
    let (frag,rem) =
        if length b > DataStream.fragmentLength then
            split b DataStream.fragmentLength
        else
            (b,[||])
    (cipherLength ki.sinfo (length frag),frag,rem)

type lengthPreds =
   CompatibleLengths of SessionInfo * int * int list

let rec estimateLengths sinfo len =
  let ls = 
    if len > DataStream.fragmentLength then 
        cipherLength sinfo DataStream.fragmentLength :: 
        estimateLengths sinfo (len - DataStream.fragmentLength)  
    else 
        [cipherLength sinfo len] in
  Pi.assume (CompatibleLengths(sinfo,len,ls));
  ls

let getFragment (sinfo:SessionInfo) (len:int) b = 
  if length(b) > DataStream.fragmentLength then
    split b DataStream.fragmentLength
  else b,[||]
