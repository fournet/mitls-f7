module Plain

open Bytes
open TLSInfo
open Algorithms
open CipherSuites

type plain = {p:bytes}

let plain (ki:KeyInfo) b = {p=b}
let repr (ki:KeyInfo) (tlen:int) p = p.p

let pad (p:int)  = Array.create p (byte (p-1))

let prepare (ki:KeyInfo) tlen ad data tag =
    let d = TLSFragment.AEADRepr ad data
    let t = MACPlain.reprMACed ki tlen tag
    let p = tlen - length d - length t  
    {p = d @| t @| pad p}

let parse ki tlen ad plain =
    let macSize = macSize (macAlg_of_ciphersuite ki.sinfo.cipher_suite) in
    let p = repr ki tlen plain
    // assert length p = tlen
    let (tmpdata, padlenb) = split p (tlen - 1) in
    let padlen = int_of_bytes padlenb in
    // use instead, as this is untrusted anyway:
    // let padlen = (int plain.[length plain - 1]) + 1
    let padstart = tlen - padlen - 1 in
    if padstart < 0 then
        (* Pretend we have a valid padding of length zero, but set we must fail *)
        let macStart = tlen - macSize - 1 in
        let (frag,mac) = split tmpdata macStart in
        let aeadF = TLSFragment.AEADFragment ad frag
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
        let (data_no_pad,pad) = split tmpdata padstart in
        match ki.sinfo.protocol_version with
        | TLS_1p0 | TLS_1p1 | TLS_1p2 ->
            let expected = Array.create padlen (byte padlen) in
            if equalBytes expected pad then
                let macStart = tlen - macSize - padlen - 1 in
                let (frag,mac) = split data_no_pad macStart in
                let aeadF = TLSFragment.AEADFragment ad frag
                let tag = MACPlain.MACed ki tlen mac
                (false,(aeadF,tag))
            else
                (* Pretend we have a valid padding of length zero, but set we must fail *)
                let macStart = tlen - macSize - 1 in
                let (frag,mac) = split tmpdata macStart in
                let aeadF = TLSFragment.AEADFragment ad frag
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
                let macStart = tlen - macSize - 1 in
                let (frag,mac) = split tmpdata macStart in
                let aeadF = TLSFragment.AEADFragment ad frag
                let tag = MACPlain.MACed ki tlen mac
                (true,(aeadF,tag))
                (*
                (* Insecurely report the error. Only TLS 1.1 and above should
                   be secure with this respect *)
                Error (RecordPadding,CheckFailed)
                *)
            else
                let macStart = tlen - macSize - padlen - 1 in
                let (frag,mac) = split data_no_pad macStart in
                let aeadF = TLSFragment.AEADFragment ad frag
                let tag = MACPlain.MACed ki tlen mac
                (false,(aeadF,tag))