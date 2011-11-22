module AEAD

open Bytes
open CipherSuites
open Algorithms
open TLSInfo
open Error
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

//CF TODO: add extra functions for gen, leak, corrupt.

let encrypt ki key iv3 clen data plain =
    match key with
    | MtE (macKey,encKey) ->
        //CF no, we need some TLSPlain.MAC. And encrypt cannot fail. 
        let text = ad_fragment ki data plain in
        match MAC.MAC ki macKey (mac_plain_to_bytes text) with
        | Error(x,y) -> Error(x,y)
        | Correct (mac) ->
            let toEncrypt = concat_fragment_mac_pad ki clen plain (bytes_to_mac mac) in
            ENC.ENC ki encKey iv3 toEncrypt

(* CF: commenting out until we get a chance to discuss:            
let CF_encrypt ki key iv3 cl data plain =
    match key with
    | MtE (macKey,encKey) ->
        let mac     = TLSPlain.MAC ki macKey data plain in
        let encoded = TLSPlain.concat_fragment_mac_pad ki cl plain mac
        ENC.ENC ki encKey iv3 encoded (* this should NOT be a Result *)

let CF_decrypt ki key iv3 data cipher =
    match key with
    | MtE (macKey, encKey) ->
        let (iv3,encoded) = ENC.DEC ki encKey iv3 cipher in
        let (plain,mac,wrongpad) = TLSPlain.split_fragment_mac_pad ki encoded in
        match ki.sinfo.protocol_version with
        | ProtocolVersionType.SSL_3p0 
        | ProtocolVersionType.TLS_1p0 ->
            (* If mustFail is true, it means some padding error occurred.
               If in early versions of TLS, insecurely report a padding error now *)
            if wrongpad then Error(RecordPadding,CheckFailed)
            else 
                match TLSPlain.VERIFY ki macKey data compr mac with
                | Correct(_)                   -> correct(iv3,plain)
                | Error(x,y)                   -> Error(x,y)
        | x when x >= ProtocolVersionType.TLS_1p1 ->
                match TLSPlain.VERIFY ki macKey data compr mac with
                | Correct(_) when not wrongpad -> correct (iv3,plain)
                | _                            -> Error(MAC,CheckFailed)
        | _ -> unexpectedError "[AEAD.decrypt] wrong protocol version"
        //CF would prefer MAC.VERIFY to return a boolean, as usual
//  | GCM (GCMKey) -> ... 
*)

let decrypt ki key iv tlen data cipher =
    match key with
    | MtE (macKey, encKey) ->
        match ENC.DEC ki encKey iv cipher with
        | Error(x,y) -> Error(x,y)
        | Correct (iv3,compr_and_mac_and_pad) ->
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
                    | Correct(_) -> correct(iv3,compr)
            | x when x >= ProtocolVersionType.TLS_1p1 ->
                match MAC.VERIFY ki macKey (mac_plain_to_bytes toVerify) (mac_to_bytes mac) with
                | Error(x,y) -> Error(x,y)
                | Correct(_) ->
                    if mustFail then
                        Error(MAC,CheckFailed)
                    else
                        correct (iv3,compr)
            | _ -> unexpectedError "[decrypt] wrong protocol version"

 (* | GCM (GCMKey) -> ... *)