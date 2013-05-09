module PRF

open Bytes
open TLSConstants
open TLSInfo

type repr = bytes
type ms = { bytes: repr }
type masterSecret = ms

#if ideal
let sample (i:msId) = {bytes = Nonce.random 48}
#endif

let coerce (i:msId) b = {bytes = b}

(** Key Derivation **) 

let keyExtensionLength aeAlg =
    match aeAlg with
        | MtE(encAlg,macAlg) ->
            let esize = encKeySize encAlg in
            let msize = macKeySize macAlg in 
              match encAlg with
                | Stream_RC4_128 | CBC_Fresh(_) -> 
                    2 * (esize + msize)
                | CBC_Stale(blockEnc) -> 
                    let bsize = blockSize blockEnc in
                      2 * (esize + bsize + msize)
        | MACOnly (macAlg) ->
            let msize = macKeySize macAlg in 
              2 * msize
#if verify
#else 
(* AEAD currently not fully implemented or verified *)               
        | AEAD(cAlg,macAlg) ->
            let aksize = aeadKeySize cAlg in
            let ivsize = aeadIVSize cAlg in
            let msize = macKeySize macAlg in
              2 * (aksize + ivsize + msize)
#endif
        | _ -> Error.unexpected "[keyExtensionLength] invoked on an invalid ciphersuite"


// This code is complex because we need to reshuffle the raw key materials  
let deriveRawKeys (i:id) (ms:ms)  =
    // we swap the CR and SR for this derivation
    let crand, srand = split i.csrConn 32
    let data = srand @| crand in
    let ae = i.aeAlg in
    let len = keyExtensionLength ae in
    let b = TLSPRF.kdf i.kdfAlg ms.bytes data len in
    match ae with
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

let deriveKeys rdId wrId (ms:masterSecret) role  =
    // at this step, we should idealize if SafeMS 
    let (ck,sk) = deriveRawKeys rdId ms
    match role with 
    | Client -> 
         StatefulLHAE.COERCE rdId Reader sk,
         StatefulLHAE.COERCE wrId Writer ck
    | Server -> 
         StatefulLHAE.COERCE rdId Reader ck,
         StatefulLHAE.COERCE wrId Writer sk

type derived = StatefulLHAE.reader * StatefulLHAE.writer 

#if ideal
type event = Waste of id 
type state =
  | Init
  | Committed of ProtocolVersion * aeAlg
  | Derived of id * id * derived
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

let keyCommit (csr:csrands) (pv:ProtocolVersion) (a:aeAlg) : unit = 
  #if ideal
  match read csr !kdlog with 
  | Init -> kdlog := update csr (Committed(pv,a)) !kdlog
  | _    -> Error.unexpected "prevented by freshness of the server random"
  #else
  ()
  #endif

let wrap rdId wrId r w = (r,w)
let wrap2 a b rw csr = Derived(a,b,rw)

//CF We could merge the two keyGen.
let keyGenClient (rdId:id) (wrId) ms =   
    #if ideal
    let pv = pv_of_id rdId
    let aeAlg = rdId.aeAlg
    let csr = rdId.csrConn
    match read csr !kdlog with
    | Committed(pv',aeAlg') when pv=pv' && aeAlg=aeAlg' && safePRF(rdId) -> 
        // we idealize the key derivation
        let (myRead,peerWrite) = StatefulLHAE.GEN rdId 
        let (peerRead,myWrite) = StatefulLHAE.GEN wrId
        let peer = wrap rdId wrId peerRead peerWrite 
        let state = wrap2 wrId rdId peer csr 
        kdlog := update csr state !kdlog;
        (myRead,myWrite)
    | _  ->
        Pi.assume(Waste(rdId));
        kdlog := update csr Wasted !kdlog;
    #endif
        deriveKeys rdId wrId ms Client

let keyGenServer (rdId:id) (wrId:id) ms =
    #if ideal
    let csr = rdId.csrConn
    match read csr !kdlog with  
    | Derived(wrId',rdId',derived) when safePRF(rdId)  ->
        // by typing the commitment, we know that rdId has matching csr pv aeAlg 
        kdlog := update csr Done !kdlog
        if rdId = wrId'
        //CF was, to be discussed: 
        //CF if rdId.msId   = wrId'.msId &&  rdId.kdfAlg = wrId'.kdfAlg              
        then  
            derived // we benefit from the client's idealization
        else
            // we generate our own ideal keys; they will lead to a verifyData mismatch
            let (myRead,peerWrite) = StatefulLHAE.GEN rdId 
            let (peerRead,myWrite) = StatefulLHAE.GEN wrId
            (myRead,myWrite)
    | _ -> 
        Pi.assume(Waste(rdId));
        kdlog := update csr Wasted !kdlog; 
    #endif
        deriveKeys rdId wrId ms Server


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
  if safeVD si then  //MK rename predicate and function
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
  && ( safeVD si  = false || mem (msi si) role data !log ) //MK: rename predicate and function
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

(* CF those do not provide useful refinements  :(
      similarly factoring out code below breaks length computations. 
let clientWriter = function 
  | Client -> Writer 
  | Server -> Reader
let clientReader = function
  | Client -> Reader 
  | Server -> Writer
*)
