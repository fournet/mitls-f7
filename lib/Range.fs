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

let ivLength e =
    let si = epochSI(e) in
    if isOnlyMACCipherSuite si.cipher_suite then
        0
    else
        match si.protocol_version with
        | SSL_3p0 | TLS_1p0 -> 0
        | TLS_1p1 | TLS_1p2 ->
            let encAlg = encAlg_of_ciphersuite si.cipher_suite in
            ivSize encAlg

let blockAlignPadding e len =
    let si = epochSI(e) in
    if isOnlyMACCipherSuite si.cipher_suite then
        0
    else
        let alg = encAlg_of_ciphersuite si.cipher_suite in
        let bs = blockSize alg in
        if bs = 0 then
            //@ Stream cipher: no Padding at all
            0
        else
            let overflow = (len + 1) % bs //@ at least one extra byte of padding
            if overflow = 0 then 1 else 1 + bs - overflow 

//@ From plaintext range to ciphertext length 
let targetLength e (rg:range) =
    let (_,h) = rg in
    let si = epochSI(e) in
    let macLen = macSize (macAlg_of_ciphersuite si.cipher_suite) in
    let ivL = ivLength e in
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
    let macSize = macSize (macAlg_of_ciphersuite si.cipher_suite) in
    let ivL = ivLength e in
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