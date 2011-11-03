module TLSPlain

open Error_handling
open Algorithms
open HS_ciphersuites
open TLSInfo
open Data

type Lengths = int list

let max_TLSPlaintext_fragment_length = 1<<<14 (* just a reminder *)
let fragmentLength = max_TLSPlaintext_fragment_length (* 1 *)

(* No way the following will typecheck. I use native byte/int conversions *)
let compute_padlen ki len =
    let alg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
    let bs = blockSize alg in
    let len_no_pad = len + 1 in (* 1 byte for the padlen byte *)
    let min_padlen =
        let overflow = len_no_pad % bs in
        if overflow = 0 then
            overflow
        else
            bs - overflow
    (* Always use fixed padding size *)
    min_padlen
    (*
    match ki.sinfo.protocol_version with
    | ProtocolVersionType.SSL_3p0 ->
        (* At most one bs. See sec 5.2.3.2 of SSL 3 draft *)
        min_padlen
    | v when v >= ProtocolVersionType.TLS_1p0 ->
        let rand = bs * (((int (OtherCrypto.mkRandom 1).[0]) - min_padlen) / bs) in 
        min_padlen + rand
    | _ -> unexpectedError "[compute_pad] invoked on wrong protocol version"
    *)

let computeAddedLen ki len =
    let cs = ki.sinfo.cipher_suite in
    match cs with
    | x when isNullCipherSuite x ->
        0
    | x when isOnlyMACCipherSuite x ->
        macLength (macAlg_of_ciphersuite cs)
    | _ -> (* GCM or MtE
                TODO: add support for GCM, now we only support MtE *)
        let macLen = macLength (macAlg_of_ciphersuite cs) in
        let padLen = compute_padlen ki (len + macLen) in
        macLen + padLen + 1

let estimateLengths ki len =
    (* Basic implementation: split at fragment length, then add some constant amount for mac and pad; last fragment treated specially.
       Even if protocol version would allow, when chosing target ciphertext length we consider a constant fixed length for padding.
       Maybe when getting a fragment given a target chipher length, we might get a random shorter fragment so as to exploit padding. *)
    let nfrag = len / fragmentLength in
    let res =
        if nfrag > 0 then
            let addedLen = computeAddedLen ki fragmentLength in          
            List.init nfrag (fun idx -> (fragmentLength + addedLen))
        else
            List.empty
    let rem = len % fragmentLength in
    if rem = 0 then
        res
    else
        let addedLen = computeAddedLen ki rem in
        res @ [ rem + addedLen ]