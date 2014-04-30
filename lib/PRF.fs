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
        | AEAD(cAlg,_) ->
            let aksize = aeadKeySize cAlg in
            let ivsize = aeadIVSize cAlg in
              2 * (aksize + ivsize)
#endif

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
#if verify
#else 
(* AEAD currently not fully implemented or verified *)
    | AEAD(encAlg,prf) ->
        match encAlg with
        | AES_128_GCM | AES_256_GCM ->
            let aksize = aeadKeySize encAlg in
            let ivsize = aeadIVSize encAlg in
            let cekb, b = split b aksize in
            let sekb, b = split b aksize in
            let civb, sivb = split b ivsize in
            let ck = (cekb @| civb) in
            let sk = (sekb @| sivb) in
            (ck,sk)
#endif


type derived = StatefulLHAE.reader * StatefulLHAE.writer 

type state =
  | Init
  | Committed of ProtocolVersion * aeAlg * negotiatedExtensions
  | Derived of id * id * derived
//  | Done 
//  | Wasted



#if ideal

type event = Mismatch of id

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

//CF to circumvent an F7 limitation?
let commit csr pv a ext = Committed(pv,a,ext)
#endif

//CF We could statically enforce the state machine.



let keyCommit (csr:csrands) (pv:ProtocolVersion) (a:aeAlg) (ext:negotiatedExtensions) : unit = 
  #if ideal
  match read csr !kdlog with 
  | Init -> 
      Pi.assume(KeyCommit(csr,pv,a,ext));
      let state = commit csr pv a ext
      kdlog := update csr state !kdlog
  | _    -> 
      Error.unexpected "prevented by freshness of the server random"
  #else
  ()
  #endif

let wrap (rdId:id) (wrId:id) r w = (r,w)
let wrap2 (a:id) (b:id) rw csr = Derived(a,b,rw)

let deriveKeys rdId wrId (ms:masterSecret) role  =
    // at this step, we should idealize if SafeMS //TODO I don't think so. 
    let (ck,sk) = deriveRawKeys rdId ms
    match role with 
    | Client -> 
         wrap rdId wrId 
            (StatefulLHAE.COERCE rdId Reader sk)
            (StatefulLHAE.COERCE wrId Writer ck)
    | Server -> 
         wrap rdId wrId
            (StatefulLHAE.COERCE rdId Reader ck)
            (StatefulLHAE.COERCE wrId Writer sk)

  
//CF We could merge the two keyGen.
let keyGenClient (rdId:id) (wrId:id) ms =   
    #if ideal
    let pv = pv_of_id rdId
    let aeAlg = rdId.aeAlg
    let csr = rdId.csrConn
    let ext = rdId.ext
    Pi.assume(KeyGenClient(csr,pv,aeAlg,ext));
    match read csr !kdlog with
    | Init ->
        // the server commits only on fresh SRs
        // hence we will never have Match(csr)
        Pi.assume(Mismatch(rdId));
        deriveKeys rdId wrId ms Client
    | Committed(pv',aeAlg',ext') when pv=pv' && aeAlg=aeAlg' && ext=ext' && safeKDF(rdId) -> 
        // we idealize the key derivation;
        // from this point AuthId and SafeId are fixed.
        let (myRead,peerWrite) = StatefulLHAE.GEN rdId 
        let (peerRead,myWrite) = StatefulLHAE.GEN wrId
        let peer = wrap wrId rdId peerRead peerWrite 
        let state = wrap2 wrId rdId peer csr 
        kdlog := update csr state !kdlog;
        (myRead,myWrite)
    | Committed(pv',aeAlg',ext') -> 
        // we logically deduce not Auth for both indexes 
        deriveKeys rdId wrId ms Client
    | Derived(_,_,_) ->
        Error.unexpected "Excluded by usage restriction (affinity)"
    #else
    deriveKeys rdId wrId ms Client
    #endif

let keyGenServer (rdId:id) (wrId:id) ms =
    #if ideal
    let csr = rdId.csrConn
    match read csr !kdlog with  
    | Init -> 
        Error.unexpected "Excluded by usage restriction (affinity)"
    | Committed(pv',aeAlg',ext') -> 
        // when SafeKDF, the client keyGens only on a fresh Ids,
        // hence we will never have AuthId(rdId) for this csr.
        //CF tricky case; revisit at some point.
        Pi.assume(Mismatch(rdId));
        deriveKeys rdId wrId ms Server
    | Derived(wrId',rdId',derived) when safeKDF(rdId)  ->
        // by typing the commitment, we know that rdId has matching csr pv aeAlg 
        if rdId = wrId'
        //CF was, to be discussed: 
        //CF if rdId.msId   = wrId'.msId &&  rdId.kdfAlg = wrId'.kdfAlg 
        //MK this looks so simple it may be just right! Maybe too good to be true?             
        then  
            derived // we benefit from the client's idealization
        else
            // we generate our own ideal keys; they will lead to a verifyData mismatch
            let (myRead,peerWrite) = StatefulLHAE.GEN rdId 
            let (peerRead,myWrite) = StatefulLHAE.GEN wrId
            (myRead,myWrite)
    | Derived(wrId',rdId',derived)  ->
        // we logically deduce not Auth for both indexes
        deriveKeys rdId wrId ms Server
    #else
    deriveKeys rdId wrId ms Server
    #endif


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
  TLSPRF.verifyData (vdAlg si) ms.bytes role data

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

