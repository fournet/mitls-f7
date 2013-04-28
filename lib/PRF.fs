module PRF

open Error
open Bytes
open TLSConstants
open TLSPRF
open TLSInfo

//MK: type rsamsindex = RSAKey.pk * ProtocolVersion * rsapms * bytes //abstract indices vs csrands alone
//let rsamsF (si:SessionInfo):rsamsindex = failwith "not efficiently implementable"

type prfAlg = // can't be folded back to the sums in TLSConstants; we need to use it in TLSPRF too. 
  | PRF_TLS_1p2 of macAlg // typically SHA256 but may depend on CS
  | PRF_TLS_1p01           // MD5 xor SHA1
  | PRF_SSL3_nested        // MD5(SHA1(...)) for extraction and keygen
  | PRF_SSL3_concat        // MD5 @| SHA1    for VerifyData tags

let prfAlgOf (si:TLSInfo.SessionInfo) =
  match si.protocol_version with
  | SSL_3p0           -> PRF_SSL3_nested 
  | TLS_1p0 | TLS_1p1 -> PRF_TLS_1p01
  | TLS_1p2           -> PRF_TLS_1p2(prfMacAlg_of_ciphersuite si.cipher_suite) 

type msIndex =  PMS.pms * // the pms and its indexes  
                csrands * // the nonces  
                prfAlg  

let strongPrfAlg (pa:prfAlg) = true
let safeMS_msIndex (msI:msIndex) =
    let (pms,csrands,prfAlg) = msI
    match pms with
    | PMS.RSAPMS(pk,cv,rsapms) -> PMS.honestRSAPMS pk cv rsapms && strongPrfAlg prfAlg
    | PMS.DHPMS(p,g,gx,gy,dhpms) -> PMS.honestDHPMS p g gx gy dhpms && strongPrfAlg prfAlg


type repr = bytes

type ms = { bytes: repr }
type masterSecret = ms

//#begin-coerce
let coerce (si:SessionInfo) b = {bytes = b}
//#end-coerce

#if ideal
let sample (si:SessionInfo)   = {bytes = random 48}
#endif


(** Key Derivation **) 

#if ideal
type keysentry = (epoch * epoch * masterSecret * bytes * StatefulLHAE.reader * StatefulLHAE.writer) 
let keyslog = ref []

// we normalize the pair to use as a shared index; 
// this function could also live in TLSInfo
let epochs (ci:ConnectionInfo) = 
  if ci.role = Client 
  then (ci.id_in, ci.id_out)
  else (ci.id_out, ci.id_in) 
#endif

let real_keyGen ci (ms:masterSecret) =
    let si = epochSI(ci.id_in) in
    let pv = si.protocol_version in
    let cs = si.cipher_suite in
    let srand = epochSRand ci.id_in in
    let crand = epochCRand ci.id_in in
    let data = srand @| crand in
    let len = getKeyExtensionLength pv cs in
    let b = prf pv cs ms.bytes tls_key_expansion data len in
    let authEnc = authencAlg_of_ciphersuite cs pv in
    match authEnc with
    | MACOnly macAlg ->
        let macKeySize = macKeySize macAlg in
        let ck,sk = split b macKeySize 
        match ci.role with 
        | Client ->
            (StatefulLHAE.COERCE ci.id_out StatefulLHAE.WriterState ck,
             StatefulLHAE.COERCE ci.id_in  StatefulLHAE.ReaderState sk)
        | Server ->
            (StatefulLHAE.COERCE ci.id_out StatefulLHAE.WriterState sk,
             StatefulLHAE.COERCE ci.id_in  StatefulLHAE.ReaderState ck)
    | MtE(encAlg,macAlg) ->
        let macKeySize = macKeySize macAlg in
        let encKeySize = encKeySize encAlg in
        match encAlg with
        | Stream_RC4_128 | CBC_Fresh(_) ->
            let cmkb, b = split b macKeySize in
            let smkb, b = split b macKeySize in
            let cekb, b = split b encKeySize in
            let sekb, b = split b encKeySize in 
            let ck = (cmkb @| cekb) in
            let sk = (smkb @| sekb) in
            match ci.role with 
            | Client ->
                (StatefulLHAE.COERCE ci.id_out StatefulLHAE.WriterState ck,
                 StatefulLHAE.COERCE ci.id_in  StatefulLHAE.ReaderState sk)
            | Server ->
                (StatefulLHAE.COERCE ci.id_out StatefulLHAE.WriterState sk,
                 StatefulLHAE.COERCE ci.id_in  StatefulLHAE.ReaderState ck)
        | CBC_Stale(alg) ->
            let ivsize = blockSize alg
            let cmkb, b = split b macKeySize in
            let smkb, b = split b macKeySize in
            let cekb, b = split b encKeySize in
            let sekb, b = split b encKeySize in
            let civb, sivb = split b ivsize in
            let ck = (cmkb @| cekb @| civb) in
            let sk = (smkb @| sekb @| sivb) in
            match ci.role with 
            | Client ->
                (StatefulLHAE.COERCE ci.id_out StatefulLHAE.WriterState ck,
                 StatefulLHAE.COERCE ci.id_in  StatefulLHAE.ReaderState sk)
            | Server ->
                (StatefulLHAE.COERCE ci.id_out StatefulLHAE.WriterState sk,
                 StatefulLHAE.COERCE ci.id_in  StatefulLHAE.ReaderState ck)
    | _ -> unexpected "[keyGen] invoked on unsupported ciphersuite"


#if ideal
let rec keysassoc
  (e1:epoch) (e2:epoch) (ms:masterSecret) (ecsr: bytes) (ks:keysentry list): 
  (StatefulLHAE.reader * StatefulLHAE.writer) option = 
    match ks with 
    | [] -> None 
    | (e1',e2',ms',ecsr',r',w')::ks' when ms=ms' && ecsr=ecsr' -> Some((r',w')) //CF not correctly indexed!?
    | (e1',e2',ms',ecsr',r',w')::ks' -> keysassoc e1 e2 ms ecsr ks'
#endif

let keyCommit (ci:ConnectionInfo):unit = 
    #if ideal
    failwith "unimplemented"
    #else
    ()
    #endif

let keyGen ci ms =
    //#begin-ideal1
    #if ideal
    //CF for typechecking against StAE, we need Auth => SafeHS_SI. 
    //CF for applying the prf assumption, we need to decide depending *only* on the session 
    if safeHS_SI (epochSI(ci.id_in)) 
    then 
        let (e1,e2) = epochs ci
        match keysassoc e1 e2 ms (epochCSRands e1) !keyslog with //add new csrand
        | Some(r,w) -> (r,w) //CF: not typing: (cWrite,cRead) -> (cWrite,cRead) 
          //MK: the order of r and w seems mixed up
        | None                    -> 
            let (myWrite,peerRead) = StatefulLHAE.GEN ci.id_out
            let (peerWrite,myRead) = StatefulLHAE.GEN ci.id_in 
            keyslog := (e1,e2,ms,epochCSRands e1, peerWrite,peerRead)::!keyslog;
            (myWrite,myRead)
    else 
    //#end-ideal1
    #endif
        real_keyGen ci ms


(** VerifyData **) 

type text = bytes
type tag = bytes

#if ideal
type entry = SessionInfo * Role * text
let log : entry list ref = ref []
// TODO use tight index instead of SessionInfo

let rec mem (si:SessionInfo) (r:Role) (t:text) (es:entry list) = 
  match es with
  | [] -> false 
  | (si',role,text)::es when si=si' && r=role && text=t -> true
  | (si',role,text)::es -> mem si r t es
#endif

// our concrete, agile MAC function
let private verifyData (si:SessionInfo) (ms:masterSecret) (role:Role) (data:text) =
  let pv = si.protocol_version in
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

let makeVerifyData si (ms:masterSecret) role data =
  let tag = verifyData si ms role data in
  #if ideal
  if safeMS_SI si then
    log := (si,role,data)::!log ;
  #endif
  tag

let checkVerifyData si ms role data tag =
  let computed = verifyData si ms role data
  equalBytes tag computed
  //#begin-ideal2
  #if ideal
  && // ideally, we return "false" when concrete 
     // verification suceeeds but shouldn't according to the log 
    ( safeMS_SI si = false ||
      mem si role data !log ) //MK: (TLSInfo.csrands si)
  //#end-ideal2
  #endif


let ssl_certificate_verify (si:SessionInfo) ms (algs:sigAlg) log =
  match algs with
  | SA_RSA -> ssl_certificate_verify ms.bytes log MD5 @| ssl_certificate_verify ms.bytes log SHA
  | SA_DSA -> ssl_certificate_verify ms.bytes log SHA
  | _      -> unexpected "[ssl_certificate_verify] invoked on a wrong signature algorithm"

