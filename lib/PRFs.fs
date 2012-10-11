module PRFs

open Bytes
open Error
open Algorithms
open Formats
open CipherSuites
open TLSInfo
open RSA
open HASH
open HMAC

type repr = bytes
type masterSecret = { bytes: repr }

// let empty_masterSecret (si:SessionInfo) : masterSecret = {bytes = [||]}

(** Low-level prf functions *)

(* SSL3 *)

let ssl_prf_int secret label seed =
  let allData = utf8 label @| secret @| seed in
  let step1 = hash SHA allData in
  let allData = secret @| step1 in
  hash MD5 allData

let ssl_prf secret seed nb = 
  let gen_label (i:int) = new System.String(char((int 'A')+i),i+1) in
  let rec apply_prf res n = 
    if n > nb then 
      Array.sub res 0 nb
    else
        let step1 = ssl_prf_int secret (gen_label (n/16)) seed in
        apply_prf (res @| step1) (n+16)
  in
  apply_prf (Array.zeroCreate 0) 0

let ssl_verifyData ms role data =
  let ssl_sender_client = [|0x43uy; 0x4Cuy; 0x4Euy; 0x54uy|] in
  let ssl_sender_server = [|0x53uy; 0x52uy; 0x56uy; 0x52uy|] in
  let ssl_sender = 
      match role with
      | Client -> ssl_sender_client 
      | Server -> ssl_sender_server
  let mm = data @| ssl_sender @| ms in
  let inner_md5 = hash MD5 (mm @| ssl_pad1_md5) in
  let outer_md5 = hash MD5 (ms @| ssl_pad2_md5 @| inner_md5) in
  let inner_sha1 = hash SHA (mm @| ssl_pad1_sha1) in
  let outer_sha1 = hash SHA (ms @| ssl_pad2_sha1 @| inner_sha1) in
  outer_md5 @| outer_sha1

(* TLS 1.0 and 1.1 *)

let xor s1 s2 nb =
  if Array.length s1 < nb || Array.length s2 < nb then
    unexpectedError "[xor] arrays too short"
  else
    let res = Array.zeroCreate nb in  
    for i=0 to nb-1 do
      res.[i] <- byte (int s1.[i] ^^^ int s2.[i])
    done;
    res

let rec p_hash_int alg secret seed len it aPrev acc =
  let aCur = HMAC alg secret aPrev in
  let pCur = HMAC alg secret (aCur @| seed) in
  if it = 1 then
    let hs = hashSize alg in
    let r = len%hs in
    let (pCur,_) = split pCur r in
    acc @| pCur
  else
    p_hash_int alg secret seed len (it-1) aCur (acc @| pCur)

let p_hash alg secret seed len =
  let hs = hashSize alg in
  let it = (len/hs)+1 in
  p_hash_int alg secret seed len it seed [||]

let tls_prf secret label seed len =
  let l_s = Array.length secret in
  let l_s1 = (l_s+1)/2 in
  let secret1 = Array.sub secret 0 l_s1 in
  let secret2 = Array.sub secret (l_s-l_s1) l_s1 in
  let newseed = (utf8 label) @| seed in
  let hmd5 = p_hash MD5 secret1 newseed len in
  let hsha1 = p_hash SHA secret2 newseed len in
  xor hmd5 hsha1 len

let tls_verifyData ms role data =
  let tls_label = 
    match role with
      | Client -> "client finished"
      | Server -> "server finished"
  let md5hash  = hash MD5 data in
  let sha1hash = hash SHA data in
  tls_prf ms tls_label (md5hash @| sha1hash) 12

(* TLS 1.2 *)

let tls12prf cs secret label seed len =
  let prfHashAlg = prfHashAlg_of_ciphersuite cs in
  let newseed = (utf8 label) @| seed in
  p_hash prfHashAlg secret newseed len

let tls12VerifyData cs ms role data =
  let tls_label = 
    match role with
      | Client -> "client finished"
      | Server -> "server finished"
  let verifyDataHashAlg = verifyDataHashAlg_of_ciphersuite cs in
  let hashResult = hash verifyDataHashAlg data in
  let verifyDataLen = verifyDataLen_of_ciphersuite cs in
  tls12prf cs ms tls_label hashResult verifyDataLen

(* Internal generic (SSL/TLS) implementation of PRF, used by purpose specific PRFs *)

let generic_prf pv cs secret label data len =
  match pv with 
  | SSL_3p0           -> ssl_prf secret data len
  | TLS_1p0 | TLS_1p1 -> tls_prf secret label data len
  | TLS_1p2           -> tls12prf cs secret label data len

(* High-level prf functions -- implement interface *)

let makeVerifyData si role (ms:masterSecret) data =
  let pv = si.protocol_version in
  match pv with 
  | SSL_3p0           -> ssl_verifyData ms.bytes role data
  | TLS_1p0 | TLS_1p1 -> tls_verifyData ms.bytes role data
  | TLS_1p2           -> let cs = si.cipher_suite in
                         tls12VerifyData cs ms.bytes role data

let checkVerifyData si role ms log expected =
    let computed = makeVerifyData si role ms log in
    equalBytes expected computed

// internal
let prfMS sinfo pmsBytes: masterSecret =
    let pv = sinfo.protocol_version in
    let cs = sinfo.cipher_suite in
    let data = sinfo.init_crand @| sinfo.init_srand in
    let res = generic_prf pv cs pmsBytes "master secret" data 48 in
    {bytes = res}

let prfSmoothRSA si (pms: RSAPlain.pms) = prfMS si (RSAPlain.leak si pms)
let prfSmoothDHE si (pms: DHE.pms)      = prfMS si (DHE.leak si pms)


let keyGen ci (ms:masterSecret) =
    let si = epochSI(ci.id_in) in
    let pv = si.protocol_version in
    let cs = si.cipher_suite in
    let srand = epochSRand ci.id_in in
    let crand = epochCRand ci.id_in in
    let data = srand @| crand in
    let len = getKeyExtensionLength pv cs in
    let b = generic_prf pv cs ms.bytes "key expansion" data len in
    let (cWrite,sWrite) =
        match cs with
        | x when isOnlyMACCipherSuite x ->
            let macKeySize = macKeySize (macAlg_of_ciphersuite cs) in
            let cmkb = Array.sub b 0 macKeySize in
            let smkb = Array.sub b macKeySize macKeySize in
            let ck = StatefulAEAD.COERCE ci.id_out cmkb in
            let sk = StatefulAEAD.COERCE ci.id_in smkb in
            (ck,sk)
        | _ ->
            let macKeySize = macKeySize (macAlg_of_ciphersuite cs) in
            let encKeySize = encKeySize (encAlg_of_ciphersuite cs) in
            let ivsize = 
                if PVRequiresExplicitIV si.protocol_version then 0
                else ivSize (encAlg_of_ciphersuite si.cipher_suite)
            let cmkb = Array.sub b 0 macKeySize in
            let smkb = Array.sub b macKeySize macKeySize in
            let cekb = Array.sub b (2*macKeySize) encKeySize in
            let sekb = Array.sub b (2*macKeySize+encKeySize) encKeySize in
            let civb = Array.sub b (2*macKeySize+2*encKeySize) ivsize in
            let sivb = Array.sub b (2*macKeySize+2*encKeySize+ivsize) ivsize in
            let ck = StatefulAEAD.COERCE ci.id_out (cmkb @| cekb @| civb) in
            let sk = StatefulAEAD.COERCE ci.id_in (smkb @| sekb @| sivb) in
            (ck,sk)
    match ci.role with 
    | Client -> cWrite,sWrite
    | Server -> sWrite,cWrite

(*  | x when IsGCM x -> ... *)

let makeTimestamp () = (* FIXME: we may need to abstract this function *)
    let t = (System.DateTime.UtcNow - new System.DateTime(1970, 1, 1))
    (int) t.TotalSeconds

//internal
let ssl_certificate_verify_hash si ms log hashAlg =
    let (pad1,pad2) =
        match hashAlg with
        | SHA -> (ssl_pad1_sha1, ssl_pad2_sha1)
        | MD5 -> (ssl_pad1_md5,  ssl_pad2_md5)
        | _ -> unexpectedError "[ssl_certificate_verify_hash] invoked on a wrong hash algorithm"
    let forStep1 = log @| ms.bytes @| pad1 in
    let step1 = hash hashAlg forStep1 in
    let forStep2 = ms.bytes @| pad2 @| step1 in
    hash hashAlg forStep2

let ssl_certificate_verify (si:SessionInfo) ms (algs:sigAlg) log =
    match algs with
    | SA_RSA ->
        ssl_certificate_verify_hash si ms log MD5 @| ssl_certificate_verify_hash si ms log SHA
    | SA_DSA ->
        ssl_certificate_verify_hash si ms log SHA
    | _ -> unexpectedError "[ssl_certificate_verify] invoked on a wrong signature algorithm"
