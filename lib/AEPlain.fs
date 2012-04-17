module AEPlain

open Bytes
open TLSInfo
open Algorithms
open CipherSuites
open DataStream
open Fragment

type data = bytes
type uns = Unsafe of KeyInfo

type AEPlain = {aep: bytes}

let AEPlain (ki:KeyInfo) (r:range) (ad:data) (b:bytes) = {aep = b}
let AERepr  (ki:KeyInfo) (r:range) (ad:data) (p:AEPlain) = p.aep

let AEConstruct (ki:KeyInfo) (r:range) (ad:data) (sb:fragment) =
  Pi.assume(Unsafe(ki));
  let b = fragmentRepr ki r sb in
    {aep = b}
let AEContents  (ki:KeyInfo) (r:range) (ad:data) (p:AEPlain) = 
  Pi.assume(Unsafe(ki));
  fragmentPlain ki r p.aep

type MACPlain = {macP: bytes}
type tag = {macT: bytes}

let macPlain (ki:KeyInfo) (rg:range) ad f =
    let fLen = bytes_of_int 2 (length f.aep) in
    let fullData = ad @| fLen in 
    {macP = fullData @| f.aep} 

let mac ki k t =
    {macT = MAC.Mac ki k t.macP}

let verify ki k text tag =
    MAC.Verify ki k text.macP tag.macT

// From Ranges to Target Length
let padLength ki len =
    // Always compute minimal padding.
    // Ranges are taking care of requiring more pad, where appropriate.
    let alg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
    let bs = blockSize alg in
    let overflow = (len + 1) % bs // at least one extra byte of padding
    if overflow = 0 then 1 else 1 + bs - overflow 
    
let rangeCipher ki (rg:DataStream.range) =
    let (_,h) = rg in
    let cs = ki.sinfo.cipher_suite in
    if isNullCipherSuite cs then
        h
    else if isOnlyMACCipherSuite cs then
        let macLen = macSize (macAlg_of_ciphersuite cs) in
        let res = h + macLen in
        res
    else
        let ivL =
            match ki.sinfo.protocol_version with
            | SSL_3p0 | TLS_1p0 -> 0
            | TLS_1p1 | TLS_1p2 ->
                let encAlg = encAlg_of_ciphersuite cs in
                ivSize encAlg
        let macLen = macSize (macAlg_of_ciphersuite cs) in
        let prePad = h + macLen in
        let padLen = padLength ki prePad in
        ivL + prePad + padLen

// And from Target Length to Ranges
let cipherRange ki tlen =
    // we could be more precise, taking into account block alignement
    let macSize = macSize (macAlg_of_ciphersuite ki.sinfo.cipher_suite) in
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

let plain (ki:KeyInfo) (tlen:nat)  b = {p=b}
let repr (ki:KeyInfo) (tlen:nat) pl = pl.p

let pad (p:int)  = createBytes p (p-1)

let ivLength ki = 
  match ki.sinfo.protocol_version with
    | SSL_3p0 | TLS_1p0 -> 0
    | TLS_1p1 | TLS_1p2 ->
        let encAlg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
          ivSize encAlg 

let encode (ki:KeyInfo) rg (ad:data) data tag =
    let ivL = ivLength ki in
    let tlen = rangeCipher ki rg in
    let p = tlen - length data.aep - length tag.macT - ivL
    (tlen, {p = data.aep @| tag.macT @| pad p})

let encodeNoPad (ki:KeyInfo) rg (ad:data) data tag =
    let tlen = rangeCipher ki rg in
    (tlen, {p = data.aep @| tag.macT})

let check_split b l = 
  if length(b) < l then failwith "split failed: FIX THIS to return BOOL + ..."
  if l < 0 then failwith "split failed: FIX THIS to return BOOL + ..."
  else Bytes.split b l

let decode ki (ad:data) tlen plain =
    let macSize = macSize (macAlg_of_ciphersuite ki.sinfo.cipher_suite) in
    let rg = cipherRange ki tlen in
    let pLen =
        match ki.sinfo.protocol_version with
        | SSL_3p0 | TLS_1p0 -> tlen
        | TLS_1p1 | TLS_1p2 ->
            let encAlg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
            tlen - (ivSize encAlg)
    if pLen <> length plain.p then
        Error.unexpectedError "[parse] tlen should be compatible with the given plaintext"
    else
    let (tmpdata, padlenb) = Bytes.split plain.p (pLen - 1) in
    let padlen = int_of_bytes padlenb in
    let padstart = pLen - padlen - 1 in
    if padstart < 0 then
        (* Pretend we have a valid padding of length zero, but set we must fail *)
        let macStart = pLen - macSize - 1 in
        let (frag,mac) = check_split tmpdata macStart in
        let aeadF = {aep = frag} in
        let tag = {macT = mac} in
        (rg,aeadF,tag,false)
        (*
        (* Evidently padding has been corrupted, or has been incorrectly generated *)
        (* in TLS1.0 we fail now, in more recent versions we fail later, see sec.6.2.3.2 Implementation Note *)
        match ki.sinfo.protocol_version with
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
        match ki.sinfo.protocol_version with
        | TLS_1p0 | TLS_1p1 | TLS_1p2 ->
            let expected = createBytes padlen padlen in
            if equalBytes expected pad then
                let macStart = pLen - macSize - padlen - 1 in
                let (frag,mac) = check_split data_no_pad macStart in
                let aeadF = {aep = frag} in
                let tag = {macT = mac} in
                (rg,aeadF,tag,true)
            else
                (* Pretend we have a valid padding of length zero, but set we must fail *)
                let macStart = pLen - macSize - 1 in
                let (frag,mac) = check_split tmpdata macStart in
                let aeadF = {aep = frag} in
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
            let encAlg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
            let bs = blockSize encAlg in
            if padlen >= bs then
                (* Pretend we have a valid padding of length zero, but set we must fail *)
                let macStart = pLen - macSize - 1 in
                let (frag,mac) = check_split tmpdata macStart in
                let aeadF = {aep = frag} in
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
                let aeadF = {aep = frag} in
                let tag = {macT = mac} in
                (rg,aeadF,tag,true)


let decodeNoPad ki (ad:data) tlen plain =
    // assert length plain.d = tlen
    let cs = ki.sinfo.cipher_suite in
    let maclen = macSize (macAlg_of_ciphersuite cs) in
    let plainLen = tlen - maclen in
// Next code is commented out, assuming we have
// - length plain.d = tlen
// - tlen >= macLen

//    if macStart < 0 || length(plain.p) < macStart then
//        (* FIXME: is this safe?
//           I (AP) think so because our locally computed mac will have some different length.
//           Also timing is not an issue, because the attacker can guess the check should fail anyway. *)
//    //CF: no, the MAC has the wrong size; I'd rather have a static precondition on the length of c.
//        let aeadF = AEADPlain.plain ki (min,max) ad plain.p
//        let tag = {macT = [||]}
//        ((min,max),aeadF,tag)
//    else
    let (frag,mac) = Bytes.split plain.p plainLen in
    let rg = (plainLen,plainLen) in
    let aeadF = {aep = frag} in
    let tag = {macT = mac} in
    (rg,aeadF,tag)
