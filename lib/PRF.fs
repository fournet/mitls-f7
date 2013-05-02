module PRF

//open Error
//open TLSError
open Bytes
open TLSConstants
open TLSInfo

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

//CF misses a definition of MsI to typecheck
let msi (si:SessionInfo) (pms:PMS.pms) = 
  (pms, csrands si, prfAlg si) 

#if ideal
// TODO
// let strongPrfAlg (pa:prfAlg) = true

let safeMS_msIndex (msi:msIndex) : bool =
    failwith "todo: failing to typecheck?!"
(*
    let (pms',csrands,prfAlg) = msi
    strongPrfAlg prfAlg && 
    match pms' with
    | PMS.RSAPMS(pk,cv,rsapms)   -> PMS.honestRSAPMS pk cv rsapms   
    | PMS.DHPMS(p,g,gx,gy,dhpms) -> PMS.honestDHPMS p g gx gy dhpms 
*)
#endif

type repr = bytes

type ms = { bytes: repr }
#if ideal
type masterSecret = msIndex * ms
let masterSecret (si:SessionInfo) (msi:msIndex) (ms:ms) = (msi,ms)
#else
type masterSecret = ms
let masterSecret si msi ms = ms
#endif

// used internally for calling concrete TLSPRF
let leak (si:SessionInfo) (ms:masterSecret) = 
#if ideal
  let (msi,ms) = ms
#endif
  ms.bytes

let coerce (si:SessionInfo) pms b = masterSecret si (msi si pms) {bytes = b}

#if ideal
let sample (si:SessionInfo) pms = masterSecret si (msi si pms) {bytes = Nonce.random 48}
#endif


(** Key Derivation **) 

(* CF those do not provide useful refinements below :(
      similarly factoring out code below breaks length computations. 
let clientWriter = function 
  | Client -> Writer 
  | Server -> Reader
let clientReader = function
  | Client -> Reader 
  | Server -> Writer
*)

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
            (StatefulLHAE.COERCE ci.id_in  Reader sk,
             StatefulLHAE.COERCE ci.id_out Writer ck)
        | Server -> 
            (StatefulLHAE.COERCE ci.id_in  Reader ck,
             StatefulLHAE.COERCE ci.id_out Writer sk)
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
                (StatefulLHAE.COERCE ci.id_in  Reader sk,
                 StatefulLHAE.COERCE ci.id_out Writer ck)
            | Server -> 
                (StatefulLHAE.COERCE ci.id_in  Reader ck,
                 StatefulLHAE.COERCE ci.id_out Writer sk)
        | CBC_Stale(alg) ->
            let cmkb, b = split b macKeySize in
            let smkb, b = split b macKeySize in
            let cekb, b = split b encKeySize in
            let sekb, b = split b encKeySize in 
            let ivsize = blockSize alg
            let civb, sivb = split b ivsize in
            let ck = (cmkb @| cekb @| civb) in
            let sk = (smkb @| sekb @| sivb) in
            match ci.role with 
            | Client -> 
                (StatefulLHAE.COERCE ci.id_in  Reader sk,
                 StatefulLHAE.COERCE ci.id_out Writer ck)
            | Server -> 
                (StatefulLHAE.COERCE ci.id_in  Reader ck,
                 StatefulLHAE.COERCE ci.id_out Writer sk)
    | _ -> Error.unexpected "[keyGen] invoked on unsupported ciphersuite"

//CF ?
//#if ideal
// we normalize the pair to use as a shared index; 
// this function could also live in TLSInfo
//let epochs (ci:ConnectionInfo) = 
//  if ci.role = Client 
//  then (ci.id_in, ci.id_out)
//  else (ci.id_out, ci.id_in) 
//#endif


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

type derived = StatefulLHAE.reader * StatefulLHAE.writer 

// TODO 
type aeAlg = int 
let ci_aeAlg (ci:ConnectionInfo) = 1 

#if ideal
type event = Waste of ConnectionInfo
type state =
  | Init
  | Committed of aeAlg
  | Derived of aeAlg * msIndex * ConnectionInfo * derived
  | Done 
  | Wasted

type kdentry = csrands * state 
let kdlog : kdentry list ref = ref [] 

let rec read csr (entries: kdentry list)  = 
  match entries with
  | []                                 -> Init 
  | (csr', s)::entries when csr = csr' -> s
  | (csr', s)::entries                 -> read csr entries

let rec update csr s (entries: kdentry list) = 
  match entries with 
  | []                                  -> [(csr,s)]
  | (csr', s')::entries when csr = csr' -> (csr,s)   :: entries 
  | (csr', s')::entries                 -> (csr', s'):: update csr s entries
#endif

//CF We could statically enforce the state machine.

let keyCommit (csr:csrands) (a:aeAlg) : unit = 
  #if ideal
  match read csr !kdlog with 
  | Init -> kdlog := update csr (Committed(a)) !kdlog
  | _    -> Error.unexpected "prevented by freshness of the server random"
  #else
  ()
  #endif

//CF We could merge the two keyGen.

let keyGenClient ci ms =
    #if ideal
    let csr = epochCSRands ci.id_in
    let (msi,ms') = ms 
    match read csr !kdlog with
    | Committed(a) when a = ci_aeAlg ci (* && honestMS && StrongKDF *) ->  // safeHS_SI (epochSI(ci.id_in)) 
        // we idealize the key derivation
        let (myRead,peerWrite) = StatefulLHAE.GEN ci.id_in 
        let (peerRead,myWrite) = StatefulLHAE.GEN ci.id_out
        //TODO we need to flip the index or the refinement
        let ci' = { id_in = ci.id_out ; id_out = ci.id_in; id_rand = ci.id_rand; role = Server }
        let peer = peerRead,peerWrite
        kdlog := update csr (Derived(a,msi,ci',(peerRead,peerWrite))) !kdlog;
        (myRead,myWrite)
    | _  ->
        Pi.assume(Waste(ci));
        kdlog := update csr Wasted !kdlog;
    #endif
        real_keyGen ci ms 

let keyGenServer ci ms =
    #if ideal
    let csr = epochCSRands ci.id_in
    match read csr !kdlog with  
    | Derived(a,msi,ci',mine) ->
        let (myRead,myWrite) = mine
        // TODO we can't have matching epochs. 
        // by typing, we should know that a matches ci 
        kdlog := update csr Done !kdlog
        if failwith "ms matches msi" 
        then  
            (myRead,myWrite) // we benefit from the client's idealization
        else
            // we generate our own ideal keys; they will lead to a verifyData mismatch
            let (myRead,peerWrite) = StatefulLHAE.GEN ci.id_in 
            let (peerRead,myWrite) = StatefulLHAE.GEN ci.id_out
            (myRead,myWrite)
    | _ -> 
        Pi.assume(Waste(ci));
        kdlog := update csr Wasted !kdlog; 
    #endif
        real_keyGen ci ms

(* was:
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
*)


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
  #if ideal
  let (msi,s) = ms
  #endif
  equalBytes tag computed
  //#begin-ideal2
  #if ideal
  && // ideally, we return "false" when concrete 
     // verification suceeeds but shouldn't according to the log 
    ( safeMS_SI si = false ||
      mem msi role data !log ) //MK: (TLSInfo.csrands si) CF:?
  //#end-ideal2
  #endif


(** ad hoc SSL3-only **)

let ssl_certificate_verify (si:SessionInfo) ms (algs:sigAlg) log =
  let s = leak si ms
  match algs with
  | SA_RSA -> TLSPRF.ssl_verifyCertificate MD5 s log @| TLSPRF.ssl_verifyCertificate SHA s log 
  | SA_DSA -> TLSPRF.ssl_verifyCertificate SHA s log 
  | _      -> Error.unexpected "[ssl_certificate_verify] invoked on a wrong signature algorithm"

