module PRF

open Bytes
open TLSConstants
open TLSInfo

#if ideal
// TODO failing to typecheck, not sure why.
// let strongPrfAlg (pa:prfAlg) = true
let safeMS_msIndex (msi:msId) : bool =
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

#if ideal
let sample (i:msId) = {bytes = Nonce.random 48}
#endif

let coerce (i:msId) b = {bytes = b}

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
let deriveRawKeys ci (ms:masterSecret) =
    let si = epochSI(ci.id_in) in
    let pv = si.protocol_version in
    let cs = si.cipher_suite in
    let srand = epochSRand ci.id_in in
    let crand = epochCRand ci.id_in in
    let data = srand @| crand in
    let len = getKeyExtensionLength pv cs in
    let b = TLSPRF.kdf (pv,cs) ms.bytes data len in
    let authEnc = aeAlg cs pv in
    match authEnc with
    | MACOnly macAlg ->
        let macKeySize = macKeySize macAlg in
        let ck,sk = split b macKeySize 
        (ck,sk) 
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
            (ck,sk)
        | CBC_Stale(alg) ->
            let cmkb, b = split b macKeySize in
            let smkb, b = split b macKeySize in
            let cekb, b = split b encKeySize in
            let sekb, b = split b encKeySize in 
            let ivsize = blockSize alg
            let civb, sivb = split b ivsize in
            let ck = (cmkb @| cekb @| civb) in
            let sk = (smkb @| sekb @| sivb) in
            (ck,sk)
    | _ -> Error.unexpected "[keyGen] invoked on unsupported ciphersuite"

let deriveKeys ci (ms:masterSecret) =
    // at this step, we should idealize if SafeMS 
    let (ck,sk) = deriveRawKeys ci ms
    match ci.role with 
    | Client -> 
         StatefulLHAE.COERCE ci.id_in  Reader sk,
         StatefulLHAE.COERCE ci.id_out Writer ck
    | Server -> 
         StatefulLHAE.COERCE ci.id_in  Reader ck,
         StatefulLHAE.COERCE ci.id_out Writer sk

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
  | Derived of aeAlg * msId * ConnectionInfo * derived
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
    match read csr !kdlog with
    | Committed(a) when a = ci_aeAlg ci (* && honestMS && StrongKDF *) ->  // safeHS_SI (epochSI(ci.id_in)) 
        // we idealize the key derivation
        let (myRead,peerWrite) = StatefulLHAE.GEN ci.id_in 
        let (peerRead,myWrite) = StatefulLHAE.GEN ci.id_out
        //TODO we need to flip the index or the refinement //MK??
        let ci' = { id_in = ci.id_out ; id_out = ci.id_in; id_rand = ci.id_rand; role = Server }
        //MK unused: let peer = peerRead,peerWrite
        let msi = msi (epochSI ci.id_in)
        kdlog := update csr (Derived(a,msi,ci',(peerRead,peerWrite))) !kdlog;
        (myRead,myWrite)
    | _  ->
        Pi.assume(Waste(ci));
        kdlog := update csr Wasted !kdlog;
    #endif
        deriveKeys ci ms 

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
        deriveKeys ci ms


(** VerifyData **) 

type text = bytes
type tag = bytes

#if ideal
type entry = msId * Role * text
let log : entry list ref = ref []

let rec mem (i:msId) (r:Role) (t:text) (es:entry list) = 
  match es with
  | [] -> false 
  | (i',role,text)::es when i=i' && r=role && text=t -> true
  | (i',role,text)::es -> mem i r t es
#endif

let private verifyData si ms role data = 
  TLSPRF.verifyData (prfAlg si) ms.bytes role data

let makeVerifyData si (ms:masterSecret) role data =
  let tag = verifyData si ms role data in
  #if ideal
  if safePRF si then  //MK rename predicate and function
    let i = msi si
    log := (i,role,data)::!log ;
  #endif
  tag

let checkVerifyData si ms role data tag =
  let computed = verifyData si ms role data
  equalBytes tag computed
  //#begin-ideal2
  #if ideal
  // we return "false" when concrete verification
  // succeeds but shouldn't according to the log 
  && ( safePRF si = false || mem (msi si) role data !log ) //MK: rename predicate and function
  //#end-ideal2
  #endif


(** ad hoc SSL3-only **)

let ssl_certificate_verify (si:SessionInfo) ms (algs:sigAlg) log =
  let s = ms.bytes
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
