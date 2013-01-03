module PRF

open Error
open Bytes
open TLSConstants
open TLSPRF
open TLSInfo

type repr = bytes
type masterSecret = { bytes: repr }

#if ideal
let log = ref []
let finish_log = ref []
let corrupted = ref []

let strong si = true  
let corrupt si = memr !corrupted si 
let honest si = if corrupt si then false else true

let sample (si:SessionInfo) = {bytes = Nonce.mkRandom 48}
#endif

let keyGen ci (ms:masterSecret) =
    let si = epochSI(ci.id_in) in
    let pv = si.protocol_version in
    let cs = si.cipher_suite in
    let srand = epochSRand ci.id_in in
    let crand = epochCRand ci.id_in in
    let data = srand @| crand in
    let len = getKeyExtensionLength pv cs in
    let b = prf pv cs ms.bytes tls_key_expansion data len in
    let cWrite, sWrite = 
    #if ideal
      if honest (epochSI(ci.id_in))
      then 
        match tryFind (fun el-> fst el = (ci,ms)) !log with
        | Some(_,(cWrite,sWrite)) -> (cWrite,sWrite)
        | None                    -> 
            let (cWrite,sRead) = StatefulAEAD.GEN ci.id_out
            let (sWrite,cRead) = StatefulAEAD.GEN ci.id_in 
            log := ((ci,ms),(cWrite,sWrite))::!log;
            (cWrite,sWrite)
      else 
    #endif
        match cs with
        | x when isOnlyMACCipherSuite x ->
            let macKeySize = macKeySize (macAlg_of_ciphersuite cs) in
            let cmkb, smkb = split b macKeySize 
            let ck = StatefulAEAD.COERCE ci.id_out cmkb in
            let sk = StatefulAEAD.COERCE ci.id_in smkb in
            (ck,sk)
        | _ ->
            let macKeySize = macKeySize (macAlg_of_ciphersuite cs) in
            let encKeySize = encKeySize (encAlg_of_ciphersuite cs) in
            let ivsize = 
                if PVRequiresExplicitIV si.protocol_version then 0
                else ivSize (encAlg_of_ciphersuite si.cipher_suite)
            let cmkb, b = split b macKeySize in
            let smkb, b = split b macKeySize in
            let cekb, b = split b encKeySize in
            let sekb, b = split b encKeySize in
            let civb, sivb = split b ivsize in
            let ck = StatefulAEAD.COERCE ci.id_out (cmkb @| cekb @| civb) in
            let sk = StatefulAEAD.COERCE ci.id_in (smkb @| sekb @| sivb) in
            (ck,sk)

    match ci.role with 
    | Client -> cWrite,sWrite
    | Server -> sWrite,cWrite


let makeVerifyData si role (ms:masterSecret) data =
  let pv = si.protocol_version in
  let tag =
    match pv with 
    | SSL_3p0           ->
        match role with
        | Client -> ssl_verifyData ms.bytes ssl_sender_client data
        | Server -> ssl_verifyData ms.bytes ssl_sender_server data
    | TLS_1p0 | TLS_1p1 ->
        match role with
        | Client -> tls_verifyData ms.bytes tls_sender_client data
        | Server -> tls_verifyData ms.bytes tls_sender_server data
    | TLS_1p2           ->
        let cs = si.cipher_suite in
        match role with
        | Client -> tls12VerifyData cs ms.bytes tls_sender_client data
        | Server -> tls12VerifyData cs ms.bytes tls_sender_server data
  #if ideal
  if honest si && strong si then 
    finish_log := (si, tag, data)::!finish_log;
  #endif
  tag

let checkVerifyData si role ms log expected =
  let computed = makeVerifyData si role ms log in
  let result = equalBytes expected computed
  #if ideal
  let result = 
    if honest si && strong si
    then result && (exists (fun el -> el=(si, expected, log)) !finish_log)
    else result 
  #endif
  result

let ssl_certificate_verify (si:SessionInfo) ms (algs:sigAlg) log =
  match algs with
  | SA_RSA -> ssl_certificate_verify ms.bytes log MD5 @| ssl_certificate_verify ms.bytes log SHA
  | SA_DSA -> ssl_certificate_verify ms.bytes log SHA
  | _      -> unexpectedError "[ssl_certificate_verify] invoked on a wrong signature algorithm"

let coerce (si:SessionInfo) b = 
  #if ideal
  corrupted := si::!corrupted;
  #endif 
  {bytes = b}