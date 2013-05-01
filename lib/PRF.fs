module PRF

open Error
open TLSError
open Bytes
open TLSConstants
open TLSInfo
//open TLSPRF

//MK: type rsamsindex = RSAKey.pk * ProtocolVersion * rsapms * bytes //abstract indices vs csrands alone
//let rsamsF (si:SessionInfo):rsamsindex = failwith "not efficiently implementable"

(* TODO we may migrate prfAlg to a tigher enumeration, as outlined below
  | PRF_TLS_1p2 of macAlg // typically SHA256 but may depend on CS
  | PRF_TLS_1p01           // MD5 xor SHA1
  | PRF_SSL3_nested        // MD5(SHA1(...)) for extraction and keygen
  | PRF_SSL3_concat        // MD5 @| SHA1    for VerifyData tags
*)

let prfAlg (si:TLSInfo.SessionInfo) = si.protocol_version, si.cipher_suite
(* TODO
  match si.protocol_version with
  | SSL_3p0           -> PRF_SSL3_nested 
  | TLS_1p0 | TLS_1p1 -> PRF_TLS_1p01
  | TLS_1p2           -> PRF_TLS_1p2(prfMacAlg_of_ciphersuite si.cipher_suite) 
*)

type msIndex =  PMS.pms * // the pms and its indexes  
                csrands * // the nonces  
                prfAlg  

#if ideal
let strongPrfAlg (pa:prfAlg) = true

let safeMS_msIndex (msI:msIndex) =
    let (pms,csrands,prfAlg) = msI
    match pms with
    | PMS.RSAPMS(pk,cv,rsapms) -> PMS.honestRSAPMS pk cv rsapms && strongPrfAlg prfAlg
    | PMS.DHPMS(p,g,gx,gy,dhpms) -> PMS.honestDHPMS p g gx gy dhpms && strongPrfAlg prfAlg
#endif

type repr = bytes

type ms = { bytes: repr }
#if ideal
type masterSecret = msIndex * ms
#else
type masterSecret = ms
#endif

let leak (si:SessionInfo) (ms:masterSecret) = 
#if ideal
  let msi,ms = ms
#endif
  ms.bytes

//#begin-coerce
let coerce (si:SessionInfo) b = {bytes = b}
//#end-coerce

#if ideal
let sample (si:SessionInfo)   = {bytes = Nonce.random 48}
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
    let b = TLSPRF.kdf (pv,cs) (leak si ms) data len in
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


// Calls to keyCommit and keyGen1 are treated as internal events of PRF. 
// SafeKDF specifically enables us to assume consistent algorithms for StAE.
// (otherwise we would not custom joint assumptions within StAE)
 
(*
predicate val SafeKDF: csr -> bool
definition SafeKDF(csr) <=> ?pv,cs. KeyCommit(csr,pv,cs) /\ KeyGen1(csr,pv,cs)  

// re: session
definition HonestMS( (pms, csr, creAlg) as msi ) <=>
  HonestPMS(pms) /\ StrongCRE(creAlg) // joint assumption  

// re: connection
// this predicate controls StAE idealization
// (relative to StAE's algorithmic strength)
// it is ideally used much before it can be proved as the HS completes.

definition SafeHS(e) <=> 
     SafeKDF(e.csr "the connection's csr") /\ 
     StrongKDF(e.kdfAlg) /\ 
     HonestMS(MsI(e))
*)

// In HS, we have 
// - KeyGen1  (e.csr, e.pv, e.cs) is a precondition to the event ClientSentCCS(e)
// - KeyCommit(e.csr, e.pv, e.cs) is a precondition to the event ServerSentCCS(e)
// - HonestMS /\ StrongVD are sufficient to guarantee 
//   matching ClientSentCCS(e) and ServerSentCCS(e), hence getting 
//   (1) SafeKDF, and 
//   (2) e is the only wide index associated with StAEIndex(e)       
//
// This enables us to prove Complete, roughly as currently defined:
//   Complete <=> (HonestPMS /\ StrongHS => SafeHS)

let keyCommit (ci:ConnectionInfo):unit = 
    #if ideal
    failwith "log into a table that msi will be used at most with those pv,cs on the second keyGen"
    #else
    ()
    #endif

let keyGen1 ci ms =
    #if ideal
    if failwith "honestMS && StrongKDF && the table records matching pv,cs for this msi" // safeHS_SI (epochSI(ci.id_in)) 
    then 
        let (e1,e2) = epochs ci
        let (myWrite,peerRead) = StatefulLHAE.GEN ci.id_out
        let (peerWrite,myRead) = StatefulLHAE.GEN ci.id_in 
        keyslog := (msi,pv,cs,peerWrite,peerRead)::!keyslog; // the semantics of SafeKDF
        (myWrite,myRead)
    else 
    #endif
        real_keyGen ci ms

let keyGen2 ci ms =
    #if ideal
    match keysassoc msi pv cs with 
    | Some(myRead,myWrite) -> (myRead,myWrite) 
    | None ->
    #endif
        real_keyGen ci ms


let keyGen ci ms =
    //#begin-ideal1
    #if ideal
    //CF for typechecking against StAE, we need Auth => SafeHS_SI. 
    //CF for applying the prf assumption, we need to decide depending *only* on the session 
    if safeHS_SI (epochSI(ci.id_in)) //TODO fix to safeKDF
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
type entry = msIndex * Role * text
let log : entry list ref = ref []
// TODO use tight index instead of SessionInfo

let rec mem (i:msIndex) (r:Role) (t:text) (es:entry list) = 
  match es with
  | [] -> false 
  | (i',role,text)::es when i=i' && r=role && text=t -> true
  | (i',role,text)::es -> mem i r t es
#endif

let verifyData si ms role data = 
  TLSPRF.verifyData (prfAlg si) (leak si ms) role data

let makeVerifyData si (ms:masterSecret) role data =
  let tag = verifyData si ms role data in
  #if ideal
  let (msi,s) = ms
  if safeMS_SI si then
    log := (msi,role,data)::!log ;
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
      let (msi,s) = ms
      mem msi role data !log ) //MK: (TLSInfo.csrands si)
  //#end-ideal2
  #endif


let ssl_certificate_verify (si:SessionInfo) ms (algs:sigAlg) log =
  let s = leak si ms
  match algs with
  | SA_RSA -> TLSPRF.ssl_verifyCertificate MD5 s log @| TLSPRF.ssl_verifyCertificate SHA s log 
  | SA_DSA -> TLSPRF.ssl_verifyCertificate SHA s log 
  | _      -> unexpected "[ssl_certificate_verify] invoked on a wrong signature algorithm"

