module Encode

open Bytes
open TLSInfo
open TLSConstants

type adata = AEADPlain.adata
type preds = Unsafe of epoch

type AEFragment = {contents: AEADPlain.plain}
type AEPlain = AEFragment

let AEPlain (e:epoch) (r:range) (ad:adata) (b:bytes) =
    // parseAD
    { contents = AEADPlain.plain e ad r b }
let AERepr  (e:epoch) (r:range) (ad:adata) (p:AEPlain) =
    // parseAD
    AEADPlain.repr e ad r p.contents

let AEConstruct (e:epoch) (r:range) (ad:adata) (sb:AEADPlain.plain) =
  {contents = sb}
let AEContents  (e:epoch) (r:range) (ad:adata) (p:AEPlain) = 
  p.contents

type MACPlain = {macP: bytes}
type tag = {macT: bytes}

let macPlain (e:epoch) (rg:range) ad f =
    Pi.assume(Unsafe(e));
    let b = AERepr e rg ad f in
    let fLen = bytes_of_int 2 (length b) in
    let fullData = ad @| fLen in 
    {macP = fullData @| b} 

let mac e k t =
    {macT = MAC.Mac e k t.macP}

let verify e k text tag =
    MAC.Verify e k text.macP tag.macT

// From Ranges to Target Length
let padLength e len =
    // Always compute minimal padding.
    // Ranges are taking care of requiring more pad, where appropriate.
    let si = epochSI(e) in
    let alg = encAlg_of_ciphersuite si.cipher_suite in
    let bs = blockSize alg in
    if bs = 0 then
        // No Padding at all
        0
    else
        let overflow = (len + 1) % bs // at least one extra byte of padding
        if overflow = 0 then 1 else 1 + bs - overflow 

let ivLength e =
    let si = epochSI(e) in
    match si.protocol_version with
    | SSL_3p0 | TLS_1p0 -> 0
    | TLS_1p1 | TLS_1p2 ->
        let encAlg = encAlg_of_ciphersuite si.cipher_suite in
          ivSize encAlg 
    
let rangeCipher e (rg:range) =
    let si = epochSI(e) in
    let (_,h) = rg in
    let cs = si.cipher_suite in
    match cs with
    | x when isOnlyMACCipherSuite x ->
        let macLen = macSize (macAlg_of_ciphersuite cs) in
        let res = h + macLen in
        if res > fragmentLength then
            Error.unexpectedError "[rangeCipher] given an invalid input range."
        else
            res
    | x when isAEADCipherSuite x ->
        let ivL = ivLength e in
        let macLen = macSize (macAlg_of_ciphersuite cs) in
        let prePad = h + macLen in
        let padLen = padLength e prePad in
        let res = ivL + prePad + padLen in
        if res > fragmentLength then
            Error.unexpectedError "[rangeCipher] given an invalid input range."
        else
            res
    | _ -> Error.unexpectedError "[rangeCipher] invoked on invalid ciphersuite."

// And from Target Length to Ranges
let cipherRange e tlen =
    // we could be more precise, taking into account block alignement
    let si = epochSI(e) in
    let macSize = macSize (macAlg_of_ciphersuite si.cipher_suite) in
    let max = tlen - macSize - 1 in
    if max < 0 then
        Error.unexpectedError "[cipherRange] the given tlen should be of a valid ciphertext"
    else
        // FIXME: in SSL/TLS1.0 pad is at most one block size. We could be more precise.
        let min = max - 255 in
        if min < 0 then
            (0,max)
        else
            (min,max)

type plain = {p:bytes}

let plain (e:epoch) (tlen:nat)  b = {p=b}
let repr (e:epoch) (tlen:nat) pl = pl.p

let encodeNoPad (e:epoch) rg (ad:adata) data tag =
    Pi.assume(Unsafe(e));
    let b = AERepr e rg ad data in
    // assert
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

let encode (e:epoch) rg (ad:adata) data tag =
    // FIXME: A bit too special for stream cipher. Would be nicer if we had a more
    // robust encoding with or without padding. (So also working for MACOnly ciphersuites)
    let si = epochSI(e) in
    let alg = encAlg_of_ciphersuite si.cipher_suite in
    match alg with
    | RC4_128 ->
        encodeNoPad e rg ad data tag
    | _ ->
    Pi.assume(Unsafe(e));
    let b = AERepr e rg ad data in
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

let check_split b l = 
  if length(b) < l then failwith "split failed: FIX THIS to return BOOL + ..."
  if l < 0 then failwith "split failed: FIX THIS to return BOOL + ..."
  else Bytes.split b l

let decodeNoPad e (ad:adata) tlen plain =
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
    Pi.assume(Unsafe(e));
    let aeadF = AEPlain e rg ad frag in
    let tag = {macT = mac} in
    (rg,aeadF,tag)

let decode e (ad:adata) tlen plain =
    // FIXME: A bit too special for stream cipher. Would be nicer if we had a more
    // robust encoding with or without padding. (So also working for MACOnly ciphersuites)
    let si = epochSI(e) in
    let alg = encAlg_of_ciphersuite si.cipher_suite in
    match alg with
    | RC4_128 ->
        let (rg,aeadF,tag) = decodeNoPad e ad tlen plain in
        (rg,aeadF,tag,true)
    | _ ->
    let macSize = macSize (macAlg_of_ciphersuite si.cipher_suite) in
    let rg = cipherRange e tlen in
    let ivL = ivLength e in
    let expected = tlen - ivL
    let pl = plain.p in
    let pLen = length pl in
    if pLen <> expected || pLen < 1 then
        Error.unexpectedError "[parse] tlen should be a valid target lentgth"
    else
    let padLenStart = pLen - 1 in
    let (tmpdata, padlenb) = Bytes.split pl padLenStart in
    let padlen = int_of_bytes padlenb in
    let padstart = pLen - padlen - 1 in
    if padstart < 0 then
        (* Pretend we have a valid padding of length zero, but set we must fail *)
        let macStart = pLen - macSize - 1 in
        let (frag,mac) = check_split tmpdata macStart in
        Pi.assume(Unsafe(e));
        let aeadF = AEPlain e rg ad frag in
        let tag = {macT = mac} in
        (rg,aeadF,tag,false)
        (*
        (* Evidently padding has been corrupted, or has been incorrectly generated *)
        (* in TLS1.0 we fail now, in more recent versions we fail later, see sec.6.2.3.2 Implementation Note *)
        match epochSI(e).protocol_version with
        | v when v >= TLS_1p1 ->
            (* Pretend we have a valid padding of length zero, but set we must fail *)
            correct(data,true)
        | v when v = SSL_3p0 || v = TLS_1p0 ->
            (* in TLS1.0/SSL we fail now, in more recent versions we fail later, see sec.6.2.3.2 Implementation Note *)
            Error (RecordPadding,CheckFailed)
        | _ -> unexpectedError "[check_padding] wrong protocol version"
        *)
    else
        let (data_no_pad,pad) = check_split tmpdata padstart in
        match si.protocol_version with
        | TLS_1p0 | TLS_1p1 | TLS_1p2 ->
            let expected = createBytes padlen padlen in
            if equalBytes expected pad then
                let macStart = pLen - macSize - padlen - 1 in
                let (frag,mac) = check_split data_no_pad macStart in
                Pi.assume(Unsafe(e));
                let aeadF = AEPlain e rg ad frag in
                let tag = {macT = mac} in
                (rg,aeadF,tag,true)
            else
                (* Pretend we have a valid padding of length zero, but set we must fail *)
                let macStart = pLen - macSize - 1 in
                let (frag,mac) = check_split tmpdata macStart in
                Pi.assume(Unsafe(e));
                let aeadF = AEPlain e rg ad frag in
                let tag = {macT = mac} in
                (rg,aeadF,tag,false)
                (*
                (* in TLS1.0 we fail now, in more recent versions we fail later, see sec.6.2.3.2 Implementation Note *)
                if  v = TLS_1p0 then
                    Error (RecordPadding,CheckFailed)
                else
                    (* Pretend we have a valid padding of length zero, but set we must fail *)
                    correct (data,true)
                *)
        | SSL_3p0 ->
            (* Padding is random in SSL_3p0, no check to be done on its content.
               However, its length should be at most one bs
               (See sec 5.2.3.2 of SSL 3 draft). Enforce this check (which
               is performed by openssl, and not by wireshark for example). *)
            let encAlg = encAlg_of_ciphersuite si.cipher_suite in
            let bs = blockSize encAlg in
            if padlen >= bs then
                (* Pretend we have a valid padding of length zero, but set we must fail *)
                let macStart = pLen - macSize - 1 in
                let (frag,mac) = check_split tmpdata macStart in
                Pi.assume(Unsafe(e));
                let aeadF = AEPlain e rg ad frag in
                let tag = {macT = mac} in
                (rg,aeadF,tag,false)
                (*
                (* Insecurely report the error. Only TLS 1.1 and above should
                   be secure with this respect *)
                Error (RecordPadding,CheckFailed)
                *)
            else
                let macStart = pLen - macSize - padlen - 1 in
                let (frag,mac) = check_split data_no_pad macStart in
                Pi.assume(Unsafe(e));
                let aeadF = AEPlain e rg ad frag in
                let tag = {macT = mac} in
                (rg,aeadF,tag,true)

let AEADPlainToAEPlain (e:epoch) (rg:range) (ad:AEADPlain.adata) p =
    AEConstruct e rg ad p
let AEPlainToAEADPlain (e:epoch) (rg:range) (ad:AEADPlain.adata) p =
    AEContents e rg ad p