module AEPlain

open Bytes
open TLSInfo
open Algorithms
open CipherSuites

type plain = {p:bytes}

let plain (ki:KeyInfo) (tlen:DataStream.range)  b = {p=b}
let repr (ki:KeyInfo) (tlen:DataStream.range) pl = pl.p

type MACPlain = {macP: bytes}
type tag = {macT: bytes}

// only for MACOnly ciphersuites, until MACOnly becomes part of AEAD
let tagRepr (ki:KeyInfo) t = t.macT
let decodeNoPad ki ad plain =
  let min,max = (length plain.p,length plain.p) in
    // assert length plain = tlen
    let cs = ki.sinfo.cipher_suite in
    let maclen = macSize (macAlg_of_ciphersuite cs) in
    let macStart = min - maclen
    if macStart < 0 || length(plain.p) < macStart then
        (* FIXME: is this safe?
           I (AP) think so because our locally computed mac will have some different length.
           Also timing is not an issue, because the attacker can guess the check should fail anyway. *)
    //CF: no, the MAC has the wrong size; I'd rather have a static precondition on the length of c.
        let aeadF = AEADPlain.plain ki (min,max) ad plain.p
        let tag = {macT = [||]}
        ((min,max),aeadF,tag)
    else
        let (frag,mac) = split plain.p macStart in
        let aeadF = AEADPlain.plain ki (min,max) ad frag
        let tag = {macT = mac}
        ((min,max),aeadF,tag)

// constructor for MACPlain
let concat (ki:KeyInfo) rg ad f =
    let fB = AEADPlain.repr ki rg ad f
    let fLen = bytes_of_int 2 (length fB) in
    let fullData = ad @| fLen in 
    {macP = fullData @| fB} 

// constructor for tag
let mac ki k t =
    {macT = MAC.MAC ki k t.macP}

let verify ki k text tag =
    MAC.VERIFY ki k text.macP tag.macT

let pad (p:int)  = createBytes p (p-1)

let encode (ki:KeyInfo) rg ad data tag =
    let d = AEADPlain.repr ki rg ad data
    let ivL =
        match ki.sinfo.protocol_version with
        | SSL_3p0 | TLS_1p0 -> 0
        | TLS_1p1 | TLS_1p2 ->
            let encAlg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
            ivSize encAlg 
    let min,max = rg in
    let p = max - length d - length tag.macT - ivL
    {p = d @| tag.macT @| pad p}

let encodeNoPad (ki:KeyInfo) rg ad data tag =
    let d = AEADPlain.repr ki rg ad data
    let ivL =
        match ki.sinfo.protocol_version with
        | SSL_3p0 | TLS_1p0 -> 0
        | TLS_1p1 | TLS_1p2 ->
            let encAlg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
            ivSize encAlg 
    let min,max = rg in
    {p = d @| tag.macT}

let check_split b l = 
  if length(b) < l then failwith "split failed: FIX THIS to return BOOL + ..."
  if l < 0 then failwith "split failed: FIX THIS to return BOOL + ..."
  else split b l

let cipherRange ki plain =
    let macSize = macSize (macAlg_of_ciphersuite ki.sinfo.cipher_suite) in
    let l = length plain.p in
    let max = l - macSize - 1 in
    if max < 0 then
        // Error. Will be handled later on
        (0,0)
    else
        let min = max - 255 in
        if min < 0 then
            (0,max)
        else
            (min,max)

let decode ki ad plain =
    let macSize = macSize (macAlg_of_ciphersuite ki.sinfo.cipher_suite) in
    let rg = cipherRange ki plain in
    let (min,max) = rg in
    let pLen =
        match ki.sinfo.protocol_version with
        | SSL_3p0 | TLS_1p0 -> max
        | TLS_1p1 | TLS_1p2 ->
            let encAlg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
            max - (ivSize encAlg)
    if pLen <> length plain.p then
        Error.unexpectedError "[parse] tlen should be compatible with the given plaintext"
    else
    let (tmpdata, padlenb) = split plain.p (pLen - 1) in
    let padlen = int_of_bytes padlenb in
    // use instead, as this is untrusted anyway:
    // let padlen = (int plain.[length plain - 1]) + 1
    let padstart = pLen - padlen - 1 in
    if padstart < 0 then
        (* Pretend we have a valid padding of length zero, but set we must fail *)
        let macStart = pLen - macSize - 1 in
        let (frag,mac) = check_split tmpdata macStart in
        let aeadF = AEADPlain.plain ki rg ad frag
        let tag = {macT = mac} in
        (rg,aeadF,tag,true)
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
                let aeadF = AEADPlain.plain ki rg ad frag
                let tag = {macT = mac} in
                (rg,aeadF,tag,false)
            else
                (* Pretend we have a valid padding of length zero, but set we must fail *)
                let macStart = pLen - macSize - 1 in
                let (frag,mac) = check_split tmpdata macStart in
                let aeadF = AEADPlain.plain ki rg ad frag
                let tag = {macT = mac} in
                (rg,aeadF,tag,true)
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
                let aeadF = AEADPlain.plain ki rg ad frag
                let tag = {macT = mac} in
                (rg,aeadF,tag,true)
                (*
                (* Insecurely report the error. Only TLS 1.1 and above should
                   be secure with this respect *)
                Error (RecordPadding,CheckFailed)
                *)
            else
                let macStart = pLen - macSize - padlen - 1 in
                let (frag,mac) = check_split data_no_pad macStart in
                let aeadF = AEADPlain.plain ki rg ad frag
                let tag = {macT = mac} in
                (rg,aeadF,tag,false)
