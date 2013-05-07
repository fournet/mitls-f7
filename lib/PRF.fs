module PRF

open Bytes
open TLSConstants
open TLSInfo

let prfAlg (si:TLSInfo.SessionInfo) = si.protocol_version, si.cipher_suite
(* TODO
  match si.protocol_version with
  | SSL_3p0           -> PRF_SSL3_nested 
  | TLS_1p0 | TLS_1p1 -> PRF_TLS_1p01
  | TLS_1p2           -> PRF_TLS_1p2(prfMacAlg_of_ciphersuite si.cipher_suite) 
*)

type msIndex =  pmsId   * // the pms and its indexes  
                csrands * // the nonces  
                prfAlg

//CF ERROR: misses a definition of MsI to typecheck
let msi (si:SessionInfo) = 
  let csr = csrands si
  let pa = prfAlg si
  (si.pmsId, csr, pa) 

#if ideal
// TODO failing to typecheck, not sure why.
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
type masterSecret = ms

// used for calling concrete TLSPRF
let private leak (si:SessionInfo) (ms:masterSecret) = 
  ms.bytes

let coerce (si:SessionInfo) pms b = {bytes = b}

#if ideal
let sample (si:SessionInfo) pms = 
  let i = msi pms
  {bytes = Nonce.random 48}
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

// This code is complex because we need to reshuffle the raw key materials  

let real_keyGen ci (ms:masterSecret) =
    let si = epochSI(ci.id_in) in
    let pv = si.protocol_version in
    let cs = si.cipher_suite in
    let srand = epochSRand ci.id_in in
    let crand = epochCRand ci.id_in in
    let data = srand @| crand in
    let len = getKeyExtensionLength pv cs in
    let b = TLSPRF.kdf (pv,cs) (leak si ms) data len in
    let authEnc = aeAlg cs pv in
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


type derived = StatefulLHAE.reader * StatefulLHAE.writer 

let ci_aeAlg (ci:ConnectionInfo) = 
  let si = 
    todo "ci.id_in must be a succEpoch"
    epochSI ci.id_in 
  aeAlg si.cipher_suite si.protocol_version 

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

//MK Still needs work
let keyGenClient ci ms =
    #if ideal
    let csr = epochCSRands ci.id_in
    let (msi,ms') = ms 
    match read csr !kdlog with
    | Committed(a) when a = ci_aeAlg ci (* && honestMS && StrongKDF *) ->  // safeHS_SI (epochSI(ci.id_in)) 
        // we idealize the key derivation
        let (myRead,peerWrite) = StatefulLHAE.GEN ci.id_in 
        let (peerRead,myWrite) = StatefulLHAE.GEN ci.id_out
        //TODO we need to flip the index or the refinement //MK??
        let ci' = { id_in = ci.id_out ; id_out = ci.id_in; id_rand = ci.id_rand; role = Server }
        //MK unused: let peer = peerRead,peerWrite
        kdlog := update csr (Derived(a,msi,ci',(peerRead,peerWrite))) !kdlog;
        (myRead,myWrite)
    | _  ->
        Pi.assume(Waste(ci));
        kdlog := update csr Wasted !kdlog;
    #endif
        real_keyGen ci ms 

//MK still needs work
let keyGenServer ci ms =
    #if ideal
    let csr = epochCSRands ci.id_in
    match read csr !kdlog with  
    | Derived(a,msi,ci',mine) ->
        let (myRead,myWrite) = mine
        // TODO we can't have matching epochs. 
        // by typing, we should know that a matches ci 
        kdlog := update csr Done !kdlog
        if false // failwith "ms matches msi" 
        then  
            //CF ERROR we need a tighter index to typecheck the key reuse.
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


(** VerifyData **) 

type text = bytes
type tag = bytes

#if ideal
type entry = msIndex * Role * text
let log : entry list ref = ref []

let rec mem (i:msIndex) (r:Role) (t:text) (es:entry list) = 
  match es with
  | [] -> false 
  | (i',role,text)::es when i=i' && r=role && text=t -> true
  | (i',role,text)::es -> mem i r t es
#endif

let private verifyData si ms role data = 
  TLSPRF.verifyData (prfAlg si) (leak si ms) role data

let makeVerifyData si (ms:masterSecret) role data =
  let tag = verifyData si ms role data in
  #if ideal
  if safeMS_SI si then  //MK rename predicate and function
    log := (msi si,role,data)::!log ;
  #endif
  tag

let checkVerifyData si ms role data tag =
  let computed = verifyData si ms role data
  equalBytes tag computed
  //#begin-ideal2
  #if ideal
  // we return "false" when concrete verification
  // succeeds but shouldn't according to the log 
  && ( safeMS_SI si = false || mem (msi si) role data !log ) //MK: rename predicate and function
  //#end-ideal2
  #endif


(** ad hoc SSL3-only **)

let ssl_certificate_verify (si:SessionInfo) ms (algs:sigAlg) log =
  let s = leak si ms
  match algs with
  | SA_RSA -> TLSPRF.ssl_verifyCertificate MD5 s log @| TLSPRF.ssl_verifyCertificate SHA s log 
  | SA_DSA -> TLSPRF.ssl_verifyCertificate SHA s log 
  | _      -> Error.unexpected "[ssl_certificate_verify] invoked on a wrong signature algorithm"



//CF ?
//#if ideal
// we normalize the pair to use as a shared index; 
// this function could also live in TLSInfo
//let epochs (ci:ConnectionInfo) = 
//  if ci.role = Client 
//  then (ci.id_in, ci.id_out)
//  else (ci.id_out, ci.id_in) 
//#endif
