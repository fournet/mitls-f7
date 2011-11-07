module AEAD

open Data
open HS_ciphersuites
open Algorithms
open TLSInfo
open Error_handling
open TLSPlain

type AEADKey =
    | MtE of MAC.macKey * ENC.symKey
 (* | GCM of GCM.GCMKey *)

(* No way the following will typecheck. I use native byte/int conversions *)
(* Commented out, should be somewhere in plain.

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

*)

let AEAD_ENC ki key ivOpt tlen data plain =
    match key with
    | MtE (macKey,encKey) ->
        let text = ad_fragment ki data plain in
        match MAC.MAC ki macKey (mac_plain_to_bytes text) with
        | Error(x,y) -> Error(x,y)
        | Correct (mac) ->
            let toEncrypt = concat_fragment_mac_pad ki tlen plain (bytes_to_mac mac) in
            ENC.ENC ki encKey ivOpt tlen toEncrypt
            
 (* | GCM (GCMKey) -> ... *)

let AEAD_DEC ki key iv tlen data cipher =
    match key with
    | MtE (macKey, encKey) ->
        match ENC.DEC ki encKey iv tlen cipher with
        | Error(x,y) -> Error(x,y)
        | Correct (ivOpt,compr_and_mac_and_pad) ->
            let (mustFail,(compr,mac)) = split_mac ki tlen compr_and_mac_and_pad in
            let toVerify = ad_fragment ki data compr in
            (* If mustFail is true, it means some padding error occurred.
               If in early versions of TLS, insecurely report a padding error now *)
            match ki.sinfo.protocol_version with
            | ProtocolVersionType.SSL_3p0 | ProtocolVersionType.TLS_1p0 ->
                if mustFail then
                    Error(RecordPadding,CheckFailed)
                else
                    match MAC.VERIFY ki macKey (mac_plain_to_bytes toVerify) (mac_to_bytes mac) with
                    | Error(x,y) -> Error(x,y)
                    | Correct(_) -> correct(ivOpt,compr)
            | x when x >= ProtocolVersionType.TLS_1p1 ->
                match MAC.VERIFY ki macKey (mac_plain_to_bytes toVerify) (mac_to_bytes mac) with
                | Error(x,y) -> Error(x,y)
                | Correct(_) ->
                    if mustFail then
                        Error(MAC,CheckFailed)
                    else
                        correct (ivOpt,compr)
            | _ -> unexpectedError "[AEAD_DEC] wrong protocol version"

 (* | GCM (GCMKey) -> ... *)