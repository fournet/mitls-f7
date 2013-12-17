module Range

open Bytes
open TLSConstants
open TLSInfo

type range = nat * nat 
type rbytes = bytes 

let sum (l0,h0) (l1,h1) =
  let l = l0 + l1
  let h = h0 + h1
  (l,h)

let ivSize (e:id) =
    let authEnc = e.aeAlg
    match authEnc with
    | MACOnly _ -> 0
    | MtE (encAlg,_) ->
        match encAlg with
        | Stream_RC4_128 -> 0
        | CBC_Stale(_) -> 0
        | CBC_Fresh(alg) -> blockSize alg
    | AEAD (_,_) -> Error.unexpected "[ivSize] invoked on wrong ciphersuite"

let fixedPadSize id =
#if TLSExt_extendedPadding
    if TLSExtensions.hasExtendedPadding id then
        2
    else
#endif
        let authEnc = id.aeAlg in
        match authEnc with
        | MACOnly _ | AEAD(_,_) -> 0
        | MtE(enc,_) ->
            match enc with
            | Stream_RC4_128 -> 0
            | CBC_Stale(_) | CBC_Fresh(_) -> 1
    
    
let maxPadSize id =
#if TLSExt_extendedPadding
    if TLSExtensions.hasExtendedPadding id then  
        fragmentLength - fixedPadSize id
    else
#endif
        let authEnc = id.aeAlg in
        match authEnc with
        | MACOnly _ | AEAD(_,_) -> 0
        | MtE(enc,_) ->
                match enc with
                | Stream_RC4_128 -> 0
                | CBC_Stale(alg) | CBC_Fresh(alg) ->
                    match id.pv with
                    | SSL_3p0 -> blockSize alg
                    | TLS_1p0 | TLS_1p1 | TLS_1p2 -> 255

let blockAlignPadding e len =
    let authEnc = e.aeAlg in
    match authEnc with
    | MACOnly _ | AEAD(_,_) -> 0
    | MtE(enc,_) ->
        match enc with
        | Stream_RC4_128 -> 0
        | CBC_Stale(alg) | CBC_Fresh(alg) ->
            let bs = blockSize alg in
            let fp = fixedPadSize e in
            let x = len + fp in
            let overflow = x % bs //@ at least fp bytes of fixed padding
            if overflow = 0 
            then overflow 
            else bs - overflow

let alignedRange e (rg:range) =
    let authEnc = e.aeAlg in
    match authEnc with
    | MtE(enc,mac) ->
        match enc with
        | Stream_RC4_128 -> rg
        | CBC_Stale(_) | CBC_Fresh(_) ->
        let (l,h) = rg in
        let macLen = macSize mac in
        let prePad = h + macLen in
        let p = blockAlignPadding e prePad in
        (l,h + p)
    | MACOnly _ | AEAD(_,_) -> rg

let extendedPad (id:id) (rg:range) (plen:nat) =
#if TLSExt_extendedPadding
    if TLSExtensions.hasExtendedPadding id then
        let rg = alignedRange id rg in
        let (_,h) = rg in
        let padlen = h - plen in
        let pad = createBytes padlen 0 in
        TLSConstants.vlbytes 2 pad
    else
#endif
        empty_bytes

//@ From plaintext range to ciphertext length 
let targetLength e (rg:range) =
    let (_,h) = rg in
    let fp = fixedPadSize e in
    let authEnc = e.aeAlg in
    match authEnc with
    | MACOnly macAlg | MtE(_,macAlg) ->
        let macLen = macSize macAlg in
        let ivL = ivSize e in
        let prePad = h + macLen in
        let padLen = blockAlignPadding e prePad in
        let res = ivL + fp + prePad + padLen in
        if res > max_TLSCipher_fragment_length then
            Error.unexpected "[targetLength] given an invalid input range."
        else
            res
    | AEAD(aeadAlg,_) ->
        let ivL = aeadRecordIVSize aeadAlg in
        let tagL = aeadTagSize aeadAlg in
        let res = ivL + fp + h + tagL in
        if res > max_TLSCipher_fragment_length then
            Error.unexpected "[targetLength] given an invalid input range."
        else
            res


let minMaxPad (i:id) =
    let maxPad = maxPadSize i in
    if maxPad = 0 then
        (0,0)
    else
        let fp = fixedPadSize i in
        (fp,maxPad) 

//@ From ciphertext length to (maximal) plaintext range
let cipherRangeClass (e:id) tlen =
    let authEnc = e.aeAlg in
    match authEnc with
    | MACOnly _ | MtE(_,_) ->
        let macSize = macSize (macAlg_of_id e) in
        let ivL = ivSize e in
        let (minPad,maxPad) = minMaxPad e in
        let max = tlen - ivL - macSize - minPad in
        if max < 0 then
            Error.unexpected "[cipherRangeClass] the given tlen should be of a valid ciphertext"
        else
            let min = max - maxPad in
            if min < 0 then
                (0,max)
            else
                (min,max)
    | AEAD(aeadAlg,_) ->
        let ivL = aeadRecordIVSize aeadAlg in
        let tagL = aeadTagSize aeadAlg in
        let (minPad,maxPad) = minMaxPad e in
        let max = tlen - ivL - tagL - minPad in
        if max < 0 then
            Error.unexpected "[cipherRangeClass] the given tlen should be of a valid ciphertext"
        else
            let min = max - maxPad in
            if min < 0 then
                (0,max)
            else
                (min,max)

let rangeClass (e:id) (r:range) =
    let tlen = targetLength e r in
    cipherRangeClass e tlen
