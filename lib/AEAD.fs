module AEAD

open Bytes
open CipherSuites
open Algorithms
open TLSInfo
open Error

type cipher = bytes

type AEADKey =
    | MtE of MAC.key * ENC.state
    | MACOnly of MAC.key
(*  |   GCM of AENC.state  *)

let GEN ki =
    let cs = ki.sinfo.cipher_suite in
    match cs with
    | x when isOnlyMACCipherSuite x ->
        let mk = MAC.GEN ki
        (MACOnly(mk), MACOnly(mk))
    | _ ->
        let mk = MAC.GEN ki in
        let (ek,dk) = ENC.GEN ki in
        (MtE(mk,ek),MtE(mk,dk))

let COERCE ki b =
    // precondition: b is of the right length. No runtime checks here.
    let cs = ki.sinfo.cipher_suite in
    match cs with
    | x when isOnlyMACCipherSuite x ->
        let mk = MAC.COERCE ki b in
        MACOnly(mk)
    | x when isAEADCipherSuite x ->
        let macKeySize = macKeySize (macAlg_of_ciphersuite cs) in
        let encKeySize = encKeySize (encAlg_of_ciphersuite cs) in
        // let ivsize = 
        //     if PVRequiresExplicitIV ki.sinfo.protocol_version then 0
        //     else ivSize (encAlg_of_ciphersuite ki.sinfo.cipher_suite)
        let (mkb,rest) = split b macKeySize in
        let (ekb,ivb) = split rest encKeySize in
        let mk = MAC.COERCE ki mkb in
        let ek = ENC.COERCE ki ekb ivb in
        MtE(mk,ek)
    | _ -> unexpectedError "[COERCE] invoked on wrong ciphersuite"

let LEAK ki k =
    match k with
    | MACOnly(mk) -> MAC.LEAK ki mk
    | MtE(mk,ek) ->
        let (k,iv) = ENC.LEAK ki ek in
        MAC.LEAK ki mk @| k @| iv

let encrypt ki key data rg plain =
    let aep = AEADPlain.AEADPlainToAEPlain ki rg data plain in
    let cs = ki.sinfo.cipher_suite in
    match (cs,key) with
    | (x, MtE (ka,ke)) when isAEADCipherSuite x ->
        let maced          = AEPlain.macPlain ki rg data aep
        let tag            = AEPlain.mac    ki ka maced  
        let (tlen,encoded) = AEPlain.encode ki rg data aep tag
        let (ke,res)       = ENC.ENC ki ke tlen encoded 
        (MtE(ka,ke),res)
    | (x,MACOnly (ka)) when isOnlyMACCipherSuite x ->
        let maced          = AEPlain.macPlain ki rg data aep
        let tag            = AEPlain.mac    ki ka maced  
        let (tlen,encoded) = AEPlain.encodeNoPad ki rg data aep tag
        (key,AEPlain.repr ki tlen encoded)
//  | GCM (k) -> ... 
    | (_,_) -> unexpectedError "[encrypt] incompatible ciphersuite-key given."
        
let decrypt ki key data cipher =
    let cs = ki.sinfo.cipher_suite in
    match (cs,key) with
    | (x, MtE (ka,ke)) when isAEADCipherSuite x ->
        let (ke,encoded)      = ENC.DEC ki ke cipher in
        let (rg,aep,tag,ok) = AEPlain.decode ki data (length cipher) encoded in
        let plain = AEADPlain.AEPlainToAEADPlain ki rg data aep in
        let maced             = AEPlain.macPlain ki rg data aep
        match ki.sinfo.protocol_version with
        | SSL_3p0 | TLS_1p0 ->
            if ok then 
              if AEPlain.verify ki ka maced tag (* padding time oracle *) 
                then
                     let key = MtE(ka,ke) in
                     let res = (key,rg,plain) in
                     correct(res)
                else Error(MAC,CheckFailed)
            else     Error(RecordPadding,CheckFailed) (* padding error oracle *)
        | TLS_1p1 | TLS_1p2 ->
            if AEPlain.verify ki ka maced tag 
            then 
              if ok 
                then
                     let key = MtE(ka,ke) in
                     let res = (key,rg,plain) in
                     correct(res)              
                else Error(MAC,CheckFailed)
            else     Error(MAC,CheckFailed)
    | (x,MACOnly (ka)) when isOnlyMACCipherSuite x ->
        let encoded        = AEPlain.plain ki (length cipher) cipher in
        let (rg,aep,tag) = AEPlain.decodeNoPad ki data (length cipher) encoded in
        let plain = AEADPlain.AEPlainToAEADPlain ki rg data aep in
        let maced          = AEPlain.macPlain ki rg data aep
        if AEPlain.verify ki ka maced tag 
          then
               let res = (key,rg,plain) in
               correct (res)
          else Error(MAC,CheckFailed)
//  | GCM (GCMKey) -> ... 
    | (_,_) -> unexpectedError "[decrypt] incompatible ciphersuite-key given."

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
