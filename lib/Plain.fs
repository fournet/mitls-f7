module Plain

open Bytes
open TLSInfo
open Algorithms
open CipherSuites

type plain = {p:bytes}

let plain (ki:KeyInfo) (tlen:DataStream.range)  b = {p=b}
let repr (ki:KeyInfo) (tlen:DataStream.range) pl = pl.p

let pad (p:int)  = createBytes p (p-1)

let prepare (ki:KeyInfo) tlen ad data tag =
    let d = TLSFragment.AEADRepr ki tlen ad data
    let t = MACPlain.reprMACed ki tlen tag
    let ivL =
        match ki.sinfo.protocol_version with
        | SSL_3p0 | TLS_1p0 -> 0
        | TLS_1p1 | TLS_1p2 ->
            let encAlg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
            ivSize encAlg 
    let min,max = tlen in
    let p = max - length d - length t - ivL
    {p = d @| t @| pad p}

let check_split b l = 
  if length(b) < l then failwith "split failed: FIX THIS to return BOOL + ..."
  if l < 0 then failwith "split failed: FIX THIS to return BOOL + ..."
  else split b l

let parse ki tlen ad plain =
    let macSize = macSize (macAlg_of_ciphersuite ki.sinfo.cipher_suite) in
    let p = repr ki tlen plain
    let min,max = tlen 
    let pLen =
        match ki.sinfo.protocol_version with
        | SSL_3p0 | TLS_1p0 -> max
        | TLS_1p1 | TLS_1p2 ->
            let encAlg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
            max - (ivSize encAlg)
    if pLen <> length p then
        Error.unexpectedError "[parse] tlen should be compatible with the given plaintext"
    else
    let (tmpdata, padlenb) = split p (pLen - 1) in
    let padlen = int_of_bytes padlenb in
    // use instead, as this is untrusted anyway:
    // let padlen = (int plain.[length plain - 1]) + 1
    let padstart = pLen - padlen - 1 in
    if padstart < 0 then
        (* Pretend we have a valid padding of length zero, but set we must fail *)
        let macStart = pLen - macSize - 1 in
        let (frag,mac) = check_split tmpdata macStart in
        let aeadF = TLSFragment.AEADPlain ki tlen ad frag
        let tag = MACPlain.MACed ki tlen mac
        (true,(aeadF,tag))
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
                let aeadF = TLSFragment.AEADPlain ki tlen ad frag
                let tag = MACPlain.MACed ki tlen mac
                (false,(aeadF,tag))
            else
                (* Pretend we have a valid padding of length zero, but set we must fail *)
                let macStart = pLen - macSize - 1 in
                let (frag,mac) = check_split tmpdata macStart in
                let aeadF = TLSFragment.AEADPlain ki tlen ad frag
                let tag = MACPlain.MACed ki tlen mac
                (true,(aeadF,tag))
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
                let aeadF = TLSFragment.AEADPlain ki tlen ad frag
                let tag = MACPlain.MACed ki tlen mac
                (true,(aeadF,tag))
                (*
                (* Insecurely report the error. Only TLS 1.1 and above should
                   be secure with this respect *)
                Error (RecordPadding,CheckFailed)
                *)
            else
                let macStart = pLen - macSize - padlen - 1 in
                let (frag,mac) = check_split data_no_pad macStart in
                let aeadF = TLSFragment.AEADPlain ki tlen ad frag
                let tag = MACPlain.MACed ki tlen mac
                (false,(aeadF,tag))
