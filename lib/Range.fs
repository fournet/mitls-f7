module Range

open Bytes
open TLSInfo
open TLSConstants

type range = nat * nat 
type rbytes = bytes 

let rangeSum (l0,h0) (l1,h1) =
  let l = l0 + l1
  let h = h0 + h1
  (l,h)

let ivSize e =
    let si = epochSI(e) in
    if isOnlyMACCipherSuite si.cipher_suite then
        0
    else
        let encAlg  = encAlg_of_ciphersuite si.cipher_suite si.protocol_version in
        match encAlg with
        | Stream_RC4_128 -> 0
        | CBC_Stale(_) -> 0
        | CBC_Fresh(alg) -> blockSize alg


let blockAlignPadding e len =
    let si = epochSI(e) in
    if isOnlyMACCipherSuite si.cipher_suite then
        0
    else
        let encAlg = encAlg_of_ciphersuite si.cipher_suite si.protocol_version in
        match encAlg with
        | Stream_RC4_128 -> 0
        | CBC_Stale(alg) | CBC_Fresh(alg) ->
            let bs = blockSize alg in
            let overflow = (len + 1) % bs //@ at least one extra byte of padding
            if overflow = 0 then 1 else 1 + bs - overflow 

//@ From plaintext range to ciphertext length 
let targetLength e (rg:range) =
    let (_,h) = rg in
    let si = epochSI(e) in
    let macLen = macSize (macAlg_of_ciphersuite si.cipher_suite si.protocol_version) in
    let ivL = ivSize e in
    let prePad = h + macLen in
    let padLen = blockAlignPadding e prePad in
    let res = ivL + prePad + padLen in
    if res > max_TLSCipher_fragment_length then
        Error.unexpectedError "[targetLength] given an invalid input range."
    else
        res

let minMaxPad si =
    let maxPad = maxPadSize si.protocol_version si.cipher_suite in
    if maxPad = 0 then
        (0,0)
    else
        (1,maxPad) 

//@ From ciphertext length to (maximal) plaintext range
let cipherRangeClass (e:epoch) tlen =
    let si = epochSI(e) in
    let macSize = macSize (macAlg_of_ciphersuite si.cipher_suite si.protocol_version) in
    let ivL = ivSize e in
    let (minPad,maxPad) = minMaxPad si in
    let max = tlen - ivL - macSize - minPad in
    if max < 0 then
        Error.unexpectedError "[cipherRangeClass] the given tlen should be of a valid ciphertext"
    else
        let min = max - maxPad in
        if min < 0 then
            let rg = (0,max) in
            rg
        else
            let rg = (min,max) in
            rg

let rangeClass (e:epoch) (r:range) =
    let tlen = targetLength e r in
    cipherRangeClass e tlen