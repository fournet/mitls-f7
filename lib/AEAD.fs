module AEAD

open Bytes
open CipherSuites
open Algorithms
open TLSInfo
open Error
// open TLSFragment
open AEADKey // the first part of this module (to break recursion)

// the first part of this module is AEADKey

let CF_encrypt id k state data rg plain =
    match k with
    | MtE (ka,ke) ->
        let maced   = MeePlain.concat id data rg plain
        let tag     = MeePlain.mac    ki id ka maced  
        let encoded = MeePlain.encode ki rg plain tag
        ENC.ENC id ke state encoded
//  | auth only -> ...
//  | GCM (GCMKey) -> ... 
        
let CF_decrypt ki k state data cipher =
    match k with
    | MtE (ka,ke) ->
        let (state,encoded)         = ENC.DEC ki ke state cipher in
        let (rg,plain,tag,decodeOk) = MeePlain.decode ki encoded in
        let maced                   = MeePlain.concat id data rg plain 
        match ki.sinfo.protocol_version with
        | SSL_3p0 | TLS_1p0 ->
            if decodeOk
            then 
                if MeePlain.verify ki ka maced tag (* padding time oracle *) 
                then correct(state,rg,plain)
                else Error(MAC,CheckFailed)
            else     Error(RecordPadding,CheckFailed) (* padding error oracle *)
        | TLS_1p1 | TLS_1p2 ->
            if MeePlain.verify ki ka maced tag 
            then 
                if decodeOk then correct (state,rg,plain)                
                else Error(MAC,CheckFailed)
            else     Error(MAC,CheckFailed)
        | _ -> unexpectedError "[AEAD.decrypt] wrong protocol version"
//  | auth only -> ...
//  | GCM (GCMKey) -> ... 

(*
let encrypt ki key iv3 tlen data plain =
    match key with
    | MtE (macKey,encKey) ->
        //CF no, we need some TLSPlain.MAC. And encrypt cannot fail. 
        let text = MACPlain.MACPlain ki tlen data plain in
        let mac = MAC.MAC {ki=ki;tlen=tlen} macKey text in
        let toEncrypt = Plain.prepare ki tlen data plain mac in
        ENC.ENC ki encKey iv3 tlen toEncrypt

let decrypt ki key iv tlen ad cipher =
    match key with
    | MtE (macKey, encKey) ->
        let (iv3,compr_and_mac_and_pad) = ENC.DEC ki encKey iv cipher in
        let (mustFail,(compr,mac)) = Plain.parse ki tlen ad compr_and_mac_and_pad in
        let toVerify = MACPlain.MACPlain ki tlen ad compr in
        (* If mustFail is true, it means some padding error occurred.
            If in early versions of TLS, insecurely report a padding error now *)
        match ki.sinfo.protocol_version with
        | SSL_3p0 | TLS_1p0 ->
            if mustFail then
                Error(RecordPadding,CheckFailed)
            else
                if MAC.VERIFY {ki=ki;tlen=tlen} macKey toVerify mac then
                    correct(iv3,compr)
                else
                    Error(MAC,CheckFailed)
        | TLS_1p1 | TLS_1p2 ->
            if MAC.VERIFY {ki=ki;tlen=tlen} macKey toVerify mac then
                if mustFail then
                    Error(MAC,CheckFailed)
                else
                    correct (iv3,compr)
            else
                Error(MAC,CheckFailed)
*)