module AEAD

open Bytes

open TLSConstants
open TLSInfo
open Error

type cipher = bytes

(***** keying *****) 

type AEADKey =
    | MtE of MAC.key * ENC.state
    | MACOnly of MAC.key
(*  | GCM of AENC.state  *)

let GEN e =
    let si = epochSI(e) in
    let cs = si.cipher_suite in
    match cs with
    | x when isOnlyMACCipherSuite x ->
        let mk = MAC.GEN e
        (MACOnly(mk), MACOnly(mk))
    | _ ->
        let mk = MAC.GEN e in
        let (ek,dk) = ENC.GEN e in
        (MtE(mk,ek),MtE(mk,dk))

let COERCE e b =
    // precondition: b is of the right length. No runtime checks here.
    let si = epochSI(e) in
    let cs = si.cipher_suite in
    if isOnlyMACCipherSuite cs then 
      let mk = MAC.COERCE e b in
      MACOnly(mk)
    else 
    if isAEADCipherSuite cs then
      let macalg = macAlg_of_ciphersuite cs in
      let encalg = encAlg_of_ciphersuite cs in
      let macKeySize = macKeySize macalg in
      let encKeySize = encKeySize encalg in
      let (mkb,rest) = split b macKeySize in
      let (ekb,ivb) = split rest encKeySize in
      let mk = MAC.COERCE e mkb in
      let ek = ENC.COERCE e ekb ivb in
      MtE(mk,ek)
    else 
      unexpectedError "[COERCE] invoked on wrong ciphersuite"

let LEAK e k =
    match k with
    | MACOnly(mk) -> MAC.LEAK e mk
    | MtE(mk,ek) ->
        let (k,iv) = ENC.LEAK e ek in
        MAC.LEAK e mk @| k @| iv

(***** authenticated encryption *****)

//CF should move elsewhere & be specified!
let ivLength e =
    let si = epochSI(e) in
    match si.protocol_version with
    | SSL_3p0 | TLS_1p0 -> 0
    | TLS_1p1 | TLS_1p2 ->
        let encAlg = encAlg_of_ciphersuite si.cipher_suite in
        ivSize encAlg

let blockAlignPadding e len =
    let si = epochSI(e) in
    let alg = encAlg_of_ciphersuite si.cipher_suite in
    let bs = blockSize alg in
    if bs = 0 then
        //@ Stream cipher: no Padding at all
        0
    else
        let overflow = (len + 1) % bs //@ at least one extra byte of padding
        if overflow = 0 then 1 else 1 + bs - overflow 

//@ From range to target ciphertext length 
let rangeCipher e (rg:range) =
    let (_,h) = rg in
    let si = epochSI(e) in
    let macLen = macSize (macAlg_of_ciphersuite si.cipher_suite) in
    let ivL = ivLength e in
    let prePad = h + macLen in
    let padLen = blockAlignPadding e prePad in
    let res = ivL + prePad + padLen in
    if res > max_TLSCipher_fragment_length then
        Error.unexpectedError "[rangeCipher] given an invalid input range."
    else
#if verify
        Pi.assume(Encode.CipherRange(e,rg,res))
#endif
        res

//@ From ciphertext length to range
let cipherRange (e:epoch) tlen =
    let si = epochSI(e) in
    let macSize = macSize (macAlg_of_ciphersuite si.cipher_suite) in
    let ivL = ivLength e in
    let max = tlen - ivL - macSize - 1 in
    if max < 0 then
        Error.unexpectedError "[cipherRange] the given tlen should be of a valid ciphertext"
    else
        (* FIXME: in SSL pad is at most one block size,
           and not always the whole 255 bytes can be used. We could be more precise. *)
        let min = max - 255 in
        if min < 0 then
            let rg = (0,max) in
#if verify
            Pi.assume(Encode.CipherRange(e,rg,tlen))
#endif
            rg
        else
            let rg = (min,max) in
#if verify
            Pi.assume(Encode.CipherRange(e,rg,tlen))
#endif
            rg

let encrypt' e key data rg plain =
    let si = epochSI(e) in
    let cs = si.cipher_suite in
    let macLen = macSize (macAlg_of_ciphersuite cs) in
    match (cs,key) with
    | (x, MtE (ka,ke)) when isAEADCipherSuite x ->
        let encAlg = encAlg_of_ciphersuite cs in
        match encAlg with
        | RC4_128 -> // stream cipher
            let tag   = Encode.mac e ka data rg plain in
            let (l,h) = rg in
            let tlen  = h + macLen in
            if l <> h || tlen > max_TLSCipher_fragment_length then
                unexpectedError "[encrypt'] given an invalid input range"
            else
                let encoded  = Encode.encodeNoPad e tlen rg data plain tag in
                let (ke,res) = ENC.ENC e ke tlen encoded 
                (MtE(ka,ke),res)
        | TDES_EDE_CBC | AES_128_CBC | AES_256_CBC -> // block cipher
            let tag  = Encode.mac e ka data rg plain in
            let tlen = rangeCipher e rg in
            let ivL  = ivLength e in
            let encoded  = Encode.encode e ivL tlen rg data plain tag in
            let (ke,res) = ENC.ENC e ke tlen encoded 
            (MtE(ka,ke),res)
    | (x,MACOnly (ka)) when isOnlyMACCipherSuite x ->
        let tag = Encode.mac e ka data rg plain in
        let (l,h) = rg in
        let tlen  = h + macLen in
        if l <> h || tlen > max_TLSCipher_fragment_length then
            unexpectedError "[encrypt']"
        let encoded = Encode.encodeNoPad e tlen rg data plain tag in
        let r = Encode.repr e tlen encoded in
        (key,r)
//  | GCM (k) -> ... 
    | (_,_) -> unexpectedError "[encrypt'] incompatible ciphersuite-key given."
        
let mteKey (e:epoch) ka ke = MtE(ka,ke)

let decrypt' e key data cipher =
    let cl = length cipher in
    if cl > max_TLSCipher_fragment_length then
        let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_bad_record_mac, reason)
    else
    let si = epochSI(e) in
    let cs = si.cipher_suite in
    let macSize = macSize (macAlg_of_ciphersuite cs) in
    match (cs,key) with
    | (x, MtE (ka,ke)) when isAEADCipherSuite x ->
        let encAlg = encAlg_of_ciphersuite cs in
        match encAlg with
        | RC4_128 -> // stream cipher
            if cl < macSize then
                (*@ It is safe to return early, because we are branching
                    on public data known to the attacker *)
                let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_bad_record_mac, reason)
            else
                let (ke,encoded) = ENC.DEC e ke cipher in
                let nk = mteKey e ka ke in
                let rg = (cl-macSize,cl-macSize) in
                let parsed = Encode.decodeNoPad e data rg cl encoded in
                match Encode.verify e ka data rg parsed with
                | Error(x,y) -> Error(x,y)
                | Correct(plain) -> correct(nk,rg,plain)
        | TDES_EDE_CBC | AES_128_CBC | AES_256_CBC -> // block cipher
            let ivL = ivLength e in
            let blockSize = blockSize (encAlg_of_ciphersuite cs) in
            if (cl - ivL < macSize + 1) || (cl % blockSize <> 0) then
                (*@ It is safe to return early, because we are branching
                    on public data known to the attacker *)
                let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_bad_record_mac, reason)
            else
                let (ke,encoded) = ENC.DEC e ke cipher in
                let nk = mteKey e ka ke in
                let rg = cipherRange e cl in
                let parsed = Encode.decode e ivL data rg cl encoded in
                match Encode.verify e ka data rg parsed with
                | Error(x,y) -> Error(x,y)
                | Correct(plain) -> correct (nk,rg,plain)
    | (x,MACOnly (ka)) when isOnlyMACCipherSuite x ->
        if cl < macSize then
            let reason = perror __SOURCE_FILE__ __LINE__ "" in Error(AD_bad_record_mac, reason)
        else
            let rg = (cl-macSize,cl-macSize) in
            let encoded = Encode.plain e (length cipher) cipher in
            let parsed  = Encode.decodeNoPad e data rg cl encoded in
            match Encode.verify e ka data rg parsed with
            | Error(x,y) -> Error(x,y)
            | Correct(plain) -> correct (key,rg,plain)
//  | GCM (GCMKey) -> ... 
    | (_,_) -> unexpectedError "[decrypt'] incompatible ciphersuite-key given."

#if ideal
type preds = 
  | CTXT of epoch * bytes * AEADPlain.plain * cipher
  | NotCTXT of epoch * bytes * cipher

type entry = epoch * AEADPlain.adata * AEADPlain.plain * ENC.cipher
let log = ref ([]: entry list) // the semantics of CTXT

let rec cmem (e:epoch) (ad:AEADPlain.adata) (c:ENC.cipher) (xs: entry list) = 
  match xs with
  | (e',ad',p,c')::_ when e=e' && ad=ad' && c=c' -> Some p
  | _::xs                  -> cmem e ad c xs 
  | []                     -> None

let safe (e:epoch) = failwith "todo"

#endif

let encrypt e key data rg plain = 
  let (key,cipher) = encrypt' e key data rg plain in
  #if ideal
  Pi.assume (CTXT(e,data,plain,cipher));
  log := (e,data,plain,cipher)::!log;
  #endif
  (key,cipher)
  
let decrypt e (key: AEADKey) data (cipher: bytes) =  
  #if ideal
  if safe e then
    match cmem e data cipher !log with
    | Some p -> // (* 1 *) decrypt' e key data cipher
                   (* 2 *) let rg = cipherRange e (length cipher) in correct (key,rg,p)
    | None   -> Encode.error  
  else decrypt' e key data cipher
  #else
  //CF don't understand CTXT and NotCTXT 
  let res = decrypt' e key data cipher in
    match res with
    | Correct r  -> let (key,rg,plain) = r in
                    #if verify
                    Pi.assume (CTXT(e,data,plain,cipher));
                    #endif
                    Correct r
    | Error(x,y) -> 
                    #if verify
                    Pi.assume (NotCTXT(e,data,cipher));
                    #endif
                    Error(x,y)
  #endif