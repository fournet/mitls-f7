module AEAD

open Data
open HS_ciphersuites
open Algorithms
open TLSInfo
open Error_handling

type AEADKey =
    | MtE of HMAC.macKey * ENC.symKey
 (* | GCM of GCM.GCMKey *)

type data = bytes (* Additional data, includes seq_num *)
type plain = bytes
type cipher = bytes

(* These functions are likely to be defined in some plain module *)
let safeConcat a b = Data.append a b
let safeLen d = Bytearray.length d
let safeSplit d n = Data.split d n

(* No way the following will typecheck. I use native byte/int conversions *)
let compute_pad ki data =
    let alg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
    let bs = blockSize alg in
    let len_no_pad = (safeLen data) + 1 in (* 1 byte for the padlen byte *)
    let min_padlen =
        let overflow = len_no_pad % bs in
        if overflow = 0 then
            overflow
        else
            bs - overflow
    match ki.sinfo.protocol_version with
    | ProtocolVersionType.SSL_3p0 ->
        (* At most one bs. See sec 5.2.3.2 of SSL 3 draft *)
        let pad = OtherCrypto.mkRandom min_padlen in
        safeConcat pad [| byte min_padlen|]
    | v when v >= ProtocolVersionType.TLS_1p0 ->
        let rand = bs * (((int (OtherCrypto.mkRandom 1).[0]) - min_padlen) / bs) in 
        let len = min_padlen + rand in
        Array.create (len+1) (byte len)
    | _ -> unexpectedError "[compute_pad] invoked on wrong protocol version"


let AEAD_ENC ki key ivOpt data plain =
    match key with
    | MtE (macKey,encKey) ->
        let text = safeConcat data plain in
        match MAC.MAC ki macKey text with
        | Error(x,y) -> Error(x,y)
        | Correct (mac) ->
            let content = safeConcat plain mac in
            let pad = compute_pad ki content in
            let toEncrypt = safeConcat content pad in
            ENC.ENC ki encKey ivOpt toEncrypt
            
 (* | GCM (GCMKey) -> ... *)


let check_padding ki (data:bytes) =
    let dlen = safeLen data in
    let (tmpdata, padlenb) = safeSplit data (dlen - 1) in
    let padlen = int padlenb.[0] in
    let padstart = dlen - padlen - 1 in
    if padstart < 0 then
        (* Evidently padding has been corrupted, or has been incorrectly generated *)
        (* in TLS1.0 we fail now, in more recent versions we fail later, see sec.6.2.3.2 Implementation Note *)
        match ki.sinfo.protocol_version with
        | v when v >= ProtocolVersionType.TLS_1p1 ->
            (* Pretend we have a valid padding of length zero, but set we must fail *)
            correct(data,true)
        | v when v = ProtocolVersionType.SSL_3p0 || v = ProtocolVersionType.TLS_1p0 ->
            (* in TLS1.0/SSL we fail now, in more recent versions we fail later, see sec.6.2.3.2 Implementation Note *)
            Error (RecordPadding,CheckFailed)
        | _ -> unexpectedError "[check_padding] wrong protocol version"
    else
        let (data_no_pad,pad) = safeSplit tmpdata padstart in
        match ki.sinfo.protocol_version with
        | v when v = ProtocolVersionType.TLS_1p0 || v = ProtocolVersionType.TLS_1p1 || v = ProtocolVersionType.TLS_1p2 ->
            let expected = Array.create padlen (byte padlen) in
            if equalBytes expected pad then
                correct(data_no_pad,false)
            else
                (* in TLS1.0 we fail now, in more recent versions we fail later, see sec.6.2.3.2 Implementation Note *)
                if  v = ProtocolVersionType.TLS_1p0 then
                    Error (RecordPadding,CheckFailed)
                else
                    (* Pretend we have a valid padding of length zero, but set we must fail *)
                    correct (data,true)
        | ProtocolVersionType.SSL_3p0 ->
            (* Padding is random in SSL_3p0, no check to be done on its content.
               However, its length should be at most one bs
               (See sec 5.2.3.2 of SSL 3 draft). Enforce this check (which
               is performed by openssl, and not by wireshark for example). *)
            let encAlg = encAlg_of_ciphersuite ki.sinfo.cipher_suite in
            let bs = blockSize encAlg in
            if padlen >= bs then
                (* Insecurely report the error. Only TLS 1.1 and above should
                   be secure with this respect *)
                Error (RecordPadding,CheckFailed)
            else
                correct(data_no_pad,false)
        | _ -> unexpectedError "[check_padding] wrong protocol version"

let AEAD_DEC ki key iv data cipher =
    match key with
    | MtE (macKey, encKey) ->
        match ENC.DEC ki encKey iv cipher with
        | Error(x,y) -> Error(x,y)
        | Correct (ivOpt,compr_and_mac_and_pad) ->
            match check_padding ki compr_and_mac_and_pad with
            | Error(x,y) -> Error(x,y)
            | Correct(compr_and_mac,mustFail) ->
                let macAlg = macAlg_of_ciphersuite ki.sinfo.cipher_suite in
                let macLen = macLength macAlg in
                let macStart = (safeLen compr_and_mac) - macLen in
                let (mustFail,macStart) = 
                    if macStart < 0 then
                        (true,0)
                    else
                        (mustFail,macStart)
                let (compr,mac) = safeSplit (compr_and_mac) macStart in
                let toVerify = safeConcat data compr in
                match MAC.VERIFY ki macKey toVerify mac with
                | Error(x,y) -> Error(x,y)
                | Correct(_) ->
                    if mustFail then
                        Error(MAC,CheckFailed)
                    else
                        correct (ivOpt,compr)

 (* | GCM (GCMKey) -> ... *)