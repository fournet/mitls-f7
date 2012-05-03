module AEAD

open Bytes
open CipherSuites
open Algorithms
open TLSInfo
open Error

type cipher = bytes

type preds = 
    CTXT of epoch * bytes * AEADPlain.AEADPlain * cipher
  | NotCTXT of epoch * bytes * cipher

type AEADKey =
    | MtE of MAC.key * ENC.state
    | MACOnly of MAC.key
(*  |   GCM of AENC.state  *)

let GEN ki =
    let si = epochSI(ki) in
    let cs = si.cipher_suite in
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
    let si = epochSI(ki) in
    let cs = si.cipher_suite in
    let onlymac = isOnlyMACCipherSuite cs in
    let aeadcs = isAEADCipherSuite cs in
      if onlymac then 
        let mk = MAC.COERCE ki b in
        MACOnly(mk)
      else 
        if aeadcs then
          let macalg = macAlg_of_ciphersuite cs in
          let encalg = encAlg_of_ciphersuite cs in
          let macKeySize = macKeySize macalg in
          let encKeySize = encKeySize encalg in
          // let ivsize = 
          //     if PVRequiresExplicitIV epochSI(ki).protocol_version then 0
          //     else ivSize (encAlg_of_ciphersuite epochSI(ki).cipher_suite)
          let (mkb,rest) = split b macKeySize in
          let (ekb,ivb) = split rest encKeySize in
          let mk = MAC.COERCE ki mkb in
          let ek = ENC.COERCE ki ekb ivb in
            MtE(mk,ek)
        else unexpectedError "[COERCE] invoked on wrong ciphersuite"

let LEAK ki k =
    match k with
    | MACOnly(mk) -> MAC.LEAK ki mk
    | MtE(mk,ek) ->
        let (k,iv) = ENC.LEAK ki ek in
        MAC.LEAK ki mk @| k @| iv

let encrypt' ki key data rg plain =
    let si = epochSI(ki) in
    let aep = AEADPlain.AEADPlainToAEPlain ki rg data plain in
    let cs = si.cipher_suite in
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
        let r = AEPlain.repr ki tlen encoded in
        (key,r)
//  | GCM (k) -> ... 
    | (_,_) -> unexpectedError "[encrypt] incompatible ciphersuite-key given."
        
let mteKey (ki:epoch) ka ke = MtE(ka,ke)


let decrypt' ki key data cipher =
    let si = epochSI(ki) in
    let cs = si.cipher_suite in
    match (cs,key) with
    | (x, MtE (ka,ke)) when isAEADCipherSuite x ->
        let (ke,encoded)      = ENC.DEC ki ke cipher in
        let nk = mteKey ki ka ke in
        let cl = length cipher in
        let (rg,aep,tag,ok) = AEPlain.decode ki data cl encoded in
        let plain = AEADPlain.AEPlainToAEADPlain ki rg data aep in
        let maced             = AEPlain.macPlain ki rg data aep
        match si.protocol_version with
        | SSL_3p0 | TLS_1p0 ->
            if ok then 
              if AEPlain.verify ki ka maced tag (* padding time oracle *) then 
                  correct (nk,rg,plain)
                else Error(MAC,CheckFailed)
            else     Error(RecordPadding,CheckFailed) (* padding error oracle *)
        | TLS_1p1 | TLS_1p2 ->
            if ok then
               if AEPlain.verify ki ka maced tag then 
                  correct (nk,rg,plain)
               else Error(MAC,CheckFailed)
            else    Error(MAC,CheckFailed)
    | (x,MACOnly (ka)) when isOnlyMACCipherSuite x ->
        let encoded        = AEPlain.plain ki (length cipher) cipher in
        let (rg,aep,tag) = AEPlain.decodeNoPad ki data (length cipher) encoded in
        let plain = AEADPlain.AEPlainToAEADPlain ki rg data aep in
        let maced          = AEPlain.macPlain ki rg data aep
        if AEPlain.verify ki ka maced tag 
        then   correct (key,rg,plain)
          else Error(MAC,CheckFailed)
//  | GCM (GCMKey) -> ... 
    | (_,_) -> unexpectedError "[decrypt] incompatible ciphersuite-key given."

let encrypt ki key data rg plain = 
  let (key,cipher) = encrypt' ki key data rg plain in
    Pi.assume (CTXT(ki,data,plain,cipher));
    (key,cipher)

let decrypt ki key data cipher = 
  let res = decrypt' ki key data cipher in
    match res with
        Correct r ->
          let (key,rg,plain) = r in
          Pi.assume (CTXT(ki,data,plain,cipher));
          Correct r
      | Error(x,y) ->
          Pi.assume (NotCTXT(ki,data,cipher));
          Error(x,y)
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
        match epochSI(ki).protocol_version with
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
