module PRF

open Bytes
open TLSConstants
open TLSPRF
open TLSInfo

type repr = bytes
type masterSecret = { bytes: repr }

#if ideal
let log = ref []
let honest_log = ref[]

let corrupt ci = exists (fun el -> el=epochSI(ci.id_in)) !honest_log
#endif

#if ideal
let sampleMS (si:SessionInfo) = {bytes = Nonce.mkRandom 48}
#endif

let keyGen ci (ms:masterSecret) =
    let si = epochSI(ci.id_in) in
    let pv = si.protocol_version in
    let cs = si.cipher_suite in
    let srand = epochSRand ci.id_in in
    let crand = epochCRand ci.id_in in
    let data = srand @| crand in
    let len = getKeyExtensionLength pv cs in
    let b = generic_prf pv cs ms.bytes tls_key_expansion data len in
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
    #if ideal
    let (cWrite,sWrite) =
        if not(corrupt ci)
        then match tryFind (fun el-> fst el = (ci,ms)) !log with
                    Some(_,(cWrite,sWrite)) -> (cWrite,sWrite)
                  | None -> 
                        let (cWrite,sRead)=StatefulAEAD.GEN ci.id_out
                        let (sWrite,cRead)=StatefulAEAD.GEN ci.id_in 
                        log := ((ci,ms),(cWrite,sWrite))::!log;
                        (cWrite,sWrite)
        else 
            (cWrite,sWrite)
    #endif

    match ci.role with 
    | Client -> cWrite,sWrite
    | Server -> sWrite,cWrite

let makeVerifyData si role (ms:masterSecret) data =
  let pv = si.protocol_version in
  match pv with 
  | SSL_3p0           ->
    match role with
    | Client ->
        ssl_verifyData ms.bytes ssl_sender_client data
    | Server ->
        ssl_verifyData ms.bytes ssl_sender_server data
  | TLS_1p0 | TLS_1p1 ->
    match role with
    | Client ->
        tls_verifyData ms.bytes tls_sender_client data
    | Server ->
        tls_verifyData ms.bytes tls_sender_server data
  | TLS_1p2           ->
    let cs = si.cipher_suite in
    match role with
    | Client ->
        tls12VerifyData cs ms.bytes tls_sender_client data
    | Server ->
        tls12VerifyData cs ms.bytes tls_sender_server data

let checkVerifyData si role ms log expected =
    let computed = makeVerifyData si role ms log in
    equalBytes expected computed

let ssl_certificate_verify (si:SessionInfo) ms (algs:sigAlg) log =
    match algs with
    | SA_RSA ->
        ssl_certificate_verify ms.bytes log MD5 @| ssl_certificate_verify ms.bytes log SHA
    | SA_DSA ->
        ssl_certificate_verify ms.bytes log SHA
    | _ -> Error.unexpectedError "[ssl_certificate_verify] invoked on a wrong signature algorithm"

let coerce (si:SessionInfo) b = 
    #if ideal
    honest_log := si::!honest_log;
    #endif 
    {bytes = b}