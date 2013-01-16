module Encode

open Bytes
open Error
open TLSInfo
open TLSConstants
open Range

#if verify
type preds = | CipherRange of epoch * range * nat
#endif

type tag = {macT: bytes}

type parsed =
    {plain: AEADPlain.plain
     tag:   tag
     ok:    bool}

let macPlain (e:epoch) (rg:range) ad f =
    let b = AEADPlain.payload e rg ad f
    ad @| vlbytes 2 b

let mac e k ad rg plain =
    let text = macPlain e rg ad plain in
    {macT = MAC.Mac e k text}

let verify e k ad rg parsed =
    let si = epochSI(e) in
    let pv = si.protocol_version in
    let text = macPlain e rg ad parsed.plain in
    let tag  = parsed.tag in
    match pv with
    | SSL_3p0 | TLS_1p0 ->
        (*@ SSL3 and TLS1 enable both timing and error padding oracles. *)
        if parsed.ok then 
          if MAC.Verify e k text tag.macT then 
            correct parsed.plain
#if DEBUG
          else let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_bad_record_mac,reason)
        else let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_decryption_failed,reason)
#else
          else Error(AD_bad_record_mac,"")
        else Error(AD_decryption_failed,"")
#endif
    | TLS_1p1 | TLS_1p2 ->
        (*@ Otherwise, we implement standard mitigation for padding oracles.
            Still, we note a small timing leak here:
            The time to verify the mac is linear in the plaintext length. *)
        if MAC.Verify e k text tag.macT then 
          if parsed.ok 
            then correct parsed.plain
#if DEBUG
          else let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_bad_record_mac,reason)
        else let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_bad_record_mac,reason) 
#else
          else Error(AD_bad_record_mac,"")
        else Error(AD_bad_record_mac,"") 
#endif

type plain = {p:bytes}

let plain (e:epoch) (tlen:nat)  b = {p=b}
let repr (e:epoch) (tlen:nat) pl = pl.p

let encodeNoPad (e:epoch) (tlen:nat) rg (ad:AEADPlain.adata) data tag =
    let b = AEADPlain.payload e rg ad data in
    let (_,h) = rg in
    if h <> length b then
        Error.unexpectedError "[encodeNoPad] invoked on an invalid range."
    else
    let payload = b @| tag.macT
    if length payload <> tlen then
        Error.unexpectedError "[encodeNoPad] Internal error."
    else
        {p = payload}

let pad (p:int)  = createBytes p (p-1)

let encode (e:epoch) (tlen:nat) rg (ad:AEADPlain.adata) data tag =
    let b = AEADPlain.payload e rg ad data in
    let lb = length b in
    let lm = length tag.macT in
    let ivL = ivLength e in
    let pl = tlen - lb - lm - ivL
    //CF here we miss refinements to prove 0 < pl <= 256
    let payload = b @| tag.macT @| pad pl
    if length payload <> tlen - ivL then
        Error.unexpectedError "[encode] Internal error."
    else
        {p = payload}

let decodeNoPad e (ad:AEADPlain.adata) rg tlen plain =
    let pl = plain.p in
    let plainLen = length pl in
    if plainLen <> tlen then
        Error.unexpectedError "[decodeNoPad] wrong target length given as input argument."
    else
    let si = epochSI(e) in
    let maclen = macSize (macAlg_of_ciphersuite si.cipher_suite) in
    let payloadLen = plainLen - maclen in
    let (frag,mac) = Bytes.split pl payloadLen in
    let aeadF = AEADPlain.plain e ad rg frag in
    let tag = {macT = mac} in
    {plain = aeadF;
     tag = tag;
     ok = true}

let decode e (ad:AEADPlain.adata) rg tlen plain =
    let si = epochSI(e) in
    let macSize = macSize (macAlg_of_ciphersuite si.cipher_suite) in
    let ivL = ivLength e in
    let expected = tlen - ivL
    let pl = plain.p in
    let pLen = length pl in
    if pLen <> expected then
        unreachable "[decode] tlen does not match plaintext length"
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
    { plain = aeadF;
      tag = tag;
      ok = flag}