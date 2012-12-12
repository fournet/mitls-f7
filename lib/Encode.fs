module Encode

open Bytes
open Error
open TLSInfo
open TLSConstants

type MACPlain = {macP: bytes}
type tag = {macT: bytes}

let macPlain (e:epoch) (rg:range) ad f =
    let b = AEADPlain.repr e ad rg f in
    let fLen = bytes_of_int 2 (length b) in
    let fullData = ad @| fLen in 
    {macP = fullData @| b} 

let mac e k t =
    {macT = MAC.Mac e k t.macP}

let verify e k text tag =
    (*@ We note a small timing leak here:
    The time to verify the mac is linear in the
    plaintext length. *)
    MAC.Verify e k text.macP tag.macT

let blockAlignPadding e len =
    let si = epochSI(e) in
    let alg = encAlg_of_ciphersuite si.cipher_suite in
    let bs = blockSize alg in
    if bs = 0 then
        //@ Stream cipher: no Padding at all
        0
    else
        let overflow = (len + 1) % bs //@ at least one extra byte of padding
        if overflow = 0 then 1 else 1 + bs - overflow 

let ivLength e =
    let si = epochSI(e) in
    match si.protocol_version with
    | SSL_3p0 | TLS_1p0 -> 0
    | TLS_1p1 | TLS_1p2 ->
        let encAlg = encAlg_of_ciphersuite si.cipher_suite in
          ivSize encAlg 

//@ From range to target ciphertext length 
let rangeCipher e (rg:range) =
    let si = epochSI(e) in
    let (_,h) = rg in
    let cs = si.cipher_suite in
    match cs with
    | x when isOnlyMACCipherSuite x ->
        let macLen = macSize (macAlg_of_ciphersuite cs) in
        let res = h + macLen in
        if res > max_TLSCipher_fragment_length then
            Error.unexpectedError "[rangeCipher] given an invalid input range."
        else
            res
    | x when isAEADCipherSuite x ->
        let ivL = ivLength e in
        let macLen = macSize (macAlg_of_ciphersuite cs) in
        let prePad = h + macLen in
        let padLen = blockAlignPadding e prePad in
        let res = ivL + prePad + padLen in
        if res > max_TLSCipher_fragment_length then
            Error.unexpectedError "[rangeCipher] given an invalid input range."
        else
            res
    | _ -> Error.unexpectedError "[rangeCipher] invoked on invalid ciphersuite."

//@ From ciphertext length to range
let cipherRange e tlen =
    let si = epochSI(e) in
    let macSize = macSize (macAlg_of_ciphersuite si.cipher_suite) in
    let max = tlen - macSize - 1 in
    if max < 0 then
        Error.unexpectedError "[cipherRange] the given tlen should be of a valid ciphertext"
    else
        // FIXME: in SSL pad is at most one block size. We could be more precise.
        let min = max - 255 in
        if min < 0 then
            (0,max)
        else
            (min,max)

type plain = {p:bytes}

let plain (e:epoch) (tlen:nat)  b = {p=b}
let repr (e:epoch) (tlen:nat) pl = pl.p

let encodeNoPad (e:epoch) rg (ad:AEADPlain.adata) data tag =
    let b = AEADPlain.repr e ad rg data in
    let (l,h) = rg in
    if l <> h || h <> length b then
        Error.unexpectedError "[encodeNoPad] invoked on an invalid range."
    else
    let tlen = rangeCipher e rg in
    let payload = b @| tag.macT
    if length payload <> tlen then
        Error.unexpectedError "[encodeNoPad] Internal error."
    else
        (tlen, {p = payload})

let pad (p:int)  = createBytes p (p-1)

let encode (e:epoch) rg (ad:AEADPlain.adata) data tag =
    let si = epochSI(e) in
    let alg = encAlg_of_ciphersuite si.cipher_suite in
    match alg with
    | RC4_128 ->
        encodeNoPad e rg ad data tag
    | _ ->
    let b = AEADPlain.repr e ad rg data in
    let ivL = ivLength e in
    let tlen = rangeCipher e rg in
    let lb = length b in
    let lm = length tag.macT in
    let pl = tlen - lb - lm - ivL
    let payload = b @| tag.macT @| pad pl
    if length payload <> tlen - ivL then
        Error.unexpectedError "[encode] Internal error."
    else
        (tlen, {p = payload})

let decodeNoPad e (ad:AEADPlain.adata) tlen plain =
    // assert length plain.d = tlen
    let si = epochSI(e) in
    let cs = si.cipher_suite in
    let maclen = macSize (macAlg_of_ciphersuite cs) in
    let pl = plain.p in
    let plainLen = length pl in
    if plainLen <> tlen || tlen < maclen then
        Error.unexpectedError "[decodeNoPad] wrong target length given as input argument."
    else
    let payloadLen = plainLen - maclen in
    let (frag,mac) = Bytes.split pl payloadLen in
    let rg = (payloadLen,payloadLen) in
    let aeadF = AEADPlain.plain e ad rg frag in
    let tag = {macT = mac} in
    (rg,aeadF,tag)

let decode e (ad:AEADPlain.adata) tlen plain =
    let si = epochSI(e) in
    let alg = encAlg_of_ciphersuite si.cipher_suite in
    match alg with
    | RC4_128 ->
        let (rg,aeadF,tag) = decodeNoPad e ad tlen plain in
        correct (rg,aeadF,tag,true)
    | _ ->
    let macSize = macSize (macAlg_of_ciphersuite si.cipher_suite) in
    let rg = cipherRange e tlen in
    let ivL = ivLength e in
    let expected = tlen - ivL
    let pl = plain.p in
    let pLen = length pl in
    if pLen <> expected then
        unexpectedError "[decode] tlen does not match plaintext length"
    else
    if pLen < macSize + 1 then
        (*@ It is safe to abort computation here, because the attacker
            already knows we received an invalid length *)
        Error(AD_illegal_parameter, perror __SOURCE_FILE__ __LINE__ "") 
    else
    let padLenStart = pLen - 1 in
    let (tmpdata, padlenb) = Bytes.split pl padLenStart in
    let padlen = int_of_bytes padlenb in
    let padstart = pLen - padlen - 1 in
    let macstart = pLen - macSize - padlen - 1 in
    let encAlg = encAlg_of_ciphersuite si.cipher_suite in
    let bs = blockSize encAlg in
    let (flag,data,padlen) =
        if padstart < 0 || macstart < 0 then
            (*@ Evidently padding has been corrupted, or has been incorrectly generated *)
            (*@ Following TLS1.1 we fail later (see RFC5246 6.2.3.2 Implementation Note) *)
            (false,tmpdata,0)
        else
            let (data_no_pad,pad) = split tmpdata padstart in
            match si.protocol_version with
            | TLS_1p0 | TLS_1p1 | TLS_1p2 ->
                (*@ We note the small timing leak here.
                    The timing of the following two lines
                    depends on padding length.
                    We could mitigate it by implementing
                    constant time comparison up to maximum padding length.*)
                let expected = createBytes padlen padlen in
                if equalBytes expected pad then
                    (true,data_no_pad,padlen)
                else
                    (false,tmpdata,0)
            | SSL_3p0 ->
               (*@ Padding is random in SSL_3p0, no check to be done on its content.
                   However, its length should be at most one bs
                   (See sec 5.2.3.2 of SSL 3 draft). Enforce this check. *)
                if padlen < bs then
                    (true,data_no_pad,padlen)
                else
                    (false,tmpdata,0)
    let macstart = pLen - macSize - padlen - 1 in
    let (frag,mac) = split data macstart in
    let aeadF = AEADPlain.plain e ad rg frag in
    let tag = {macT = mac} in
    correct (rg,aeadF,tag,flag)