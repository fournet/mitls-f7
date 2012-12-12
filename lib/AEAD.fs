module AEAD

open Bytes

open TLSConstants
open TLSInfo
open Error

type cipher = bytes

#if verify
type preds = 
    CTXT of epoch * bytes * AEADPlain.plain * cipher
  | NotCTXT of epoch * bytes * cipher
#endif

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
    let cs = si.cipher_suite in
    match (cs,key) with
    | (x, MtE (ka,ke)) when isAEADCipherSuite x ->
        let maced          = Encode.macPlain ki rg data plain
        let tag            = Encode.mac    ki ka maced  
        let (tlen,encoded) = Encode.encode ki rg data plain tag
        let (ke,res)       = ENC.ENC ki ke tlen encoded 
        (MtE(ka,ke),res)
    | (x,MACOnly (ka)) when isOnlyMACCipherSuite x ->
        let maced          = Encode.macPlain ki rg data plain
        let tag            = Encode.mac    ki ka maced  
        let (tlen,encoded) = Encode.encodeNoPad ki rg data plain tag
        let r = Encode.repr ki tlen encoded in
        (key,r)
//  | GCM (k) -> ... 
    | (_,_) -> unexpectedError "[encrypt'] incompatible ciphersuite-key given."
        
let mteKey (ki:epoch) ka ke = MtE(ka,ke)

let decrypt' ki key data cipher =
    let si = epochSI(ki) in
    let cs = si.cipher_suite in
    match (cs,key) with
    | (x, MtE (ka,ke)) when isAEADCipherSuite x ->
        let (ke,encoded)      = ENC.DEC ki ke cipher in
        let nk = mteKey ki ka ke in
        let cl = length cipher in
        match Encode.decode ki data cl encoded with
        | Error(x,y) -> Error(x,y)
        | Correct(res) ->
        let (rg,plain,tag,ok) = res in
        let maced             = Encode.macPlain ki rg data plain in
        match si.protocol_version with
        | SSL_3p0 | TLS_1p0 ->
            (*@ SSL3 and TLS1 enable both timing and error padding oracles. *)
            if ok then 
              if Encode.verify ki ka maced tag then 
                  correct (nk,rg,plain)
              else let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_bad_record_mac, reason)
            else let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_decryption_failed, reason)
        | TLS_1p1 | TLS_1p2 ->
            (*@ We implement standard mitigiation for padding oracles.
                Still, we are aware of small timing leaks in verify and decode,
                whose timing can be linked to the length of the plaintext. *)
            if Encode.verify ki ka maced tag then 
               if ok then
                  correct (nk,rg,plain)
               else let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_bad_record_mac, reason)
            else let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_bad_record_mac, reason)
    | (x,MACOnly (ka)) when isOnlyMACCipherSuite x ->
        let encoded        = Encode.plain ki (length cipher) cipher in
        let (rg,plain,tag) = Encode.decodeNoPad ki data (length cipher) encoded in
        let maced          = Encode.macPlain ki rg data plain
        if Encode.verify ki ka maced tag 
        then   correct (key,rg,plain)
          else let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_bad_record_mac, reason)
//  | GCM (GCMKey) -> ... 
    | (_,_) -> unexpectedError "[decrypt'] incompatible ciphersuite-key given."

let encrypt ki key data rg plain = 
    let (key,cipher) = encrypt' ki key data rg plain in
#if verify
    Pi.assume (CTXT(ki,data,plain,cipher));
#endif
    (key,cipher)

let decrypt ki key data cipher = 
  let res = decrypt' ki key data cipher in
    match res with
        Correct r ->
          let (key,rg,plain) = r in
#if verify
          Pi.assume (CTXT(ki,data,plain,cipher));
#endif
          Correct r
      | Error(x,y) ->
#if verify
          Pi.assume (NotCTXT(ki,data,cipher));
#endif
          Error(x,y)
