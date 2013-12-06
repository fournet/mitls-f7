﻿module TLSInfo

open Bytes
open Date
open TLSConstants
open PMS

type rw =
    | Reader
    | Writer

type sessionID = bytes
type preRole =
    | Client
    | Server
type Role = preRole

// Client/Server randomness
type random = bytes
type crand = random
type srand = random
type csrands = bytes

type cVerifyData = bytes (* ClientFinished payload *)
type sVerifyData = bytes (* ServerFinished payload *)

type sessionHash = bytes

// Defined here to not depend on TLSExtension
type negotiatedExtension =
    | NE_extended_ms
    | NE_extended_padding

type negotiatedExtensions = negotiatedExtension list

let noCsr:csrands = Nonce.random 64

type pmsId = 
  | NoPmsId 
  | SomePmsId of PMS.pms
let pmsId (pms:PMS.pms) = SomePmsId(pms)
let noPmsId = NoPmsId

type pmsData =
  | PMSUnset
  | RSAPMS of RSAKey.pk * ProtocolVersion * bytes
  | DHPMS  of DHGroup.p * DHGroup.g * DHGroup.elt * DHGroup.elt

type msId = 
  pmsId * 
  csrands *                                          
  creAlg  

let noMsId = noPmsId, noCsr, CRE_SSL3_nested    

type SessionInfo = {
    init_crand: crand;
    init_srand: srand;
    protocol_version: ProtocolVersion;
    cipher_suite: cipherSuite;
    compression: Compression;
    extensions: negotiatedExtensions;
    pmsId: pmsId;
    pmsData: pmsData;
    session_hash: sessionHash;
    client_auth: bool;
    clientID: Cert.cert list;
    serverID: Cert.cert list;
    sessionID: sessionID;
    }

let csrands sinfo = 
    sinfo.init_crand @| sinfo.init_srand

let prfAlg (si:SessionInfo) = 
  si.protocol_version, si.cipher_suite

let creAlg (si:SessionInfo) =
  match si.protocol_version with
  | SSL_3p0           -> CRE_SSL3_nested 
  | TLS_1p0 | TLS_1p1 -> let x = CRE_TLS_1p01(extract_label) in x
  | TLS_1p2           -> let ma = prfMacAlg_of_ciphersuite si.cipher_suite
                         CRE_TLS_1p2(extract_label,ma)

let creAlg_extended (si:SessionInfo) =
  match si.protocol_version with
  | SSL_3p0           -> CRE_SSL3_nested 
  | TLS_1p0 | TLS_1p1 -> let x = CRE_TLS_1p01(extended_extract_label) in x
  | TLS_1p2           -> let ma = prfMacAlg_of_ciphersuite si.cipher_suite
                         CRE_TLS_1p2(extended_extract_label,ma) 

let kdfAlg (si:SessionInfo) = 
  si.protocol_version, si.cipher_suite

let vdAlg (si:SessionInfo) = 
  si.protocol_version, si.cipher_suite


let msi (si:SessionInfo) = 
  let csr = csrands si
  let ca = creAlg si
  (si.pmsId, csr, ca) 



type preEpoch =
    | InitEpoch of Role
    | SuccEpoch of crand * srand * SessionInfo * preEpoch
type epoch = preEpoch
type succEpoch = preEpoch
type openEpoch = preEpoch

let isInitEpoch e = 
    match e with
    | InitEpoch (_) -> true
    | SuccEpoch (_,_,_,_) -> false

let epochSI e =
    match e with
    | InitEpoch (d) -> Error.unexpected "[epochSI] invoked on initial epoch."
    | SuccEpoch (cr,sr,si,pe) -> si

let epochSRand e =
    match e with
    | InitEpoch (d) -> Error.unexpected "[epochSRand] invoked on initial epoch."
    | SuccEpoch (cr,sr,si,pe) -> sr

let epochCRand e =
    match e with
    | InitEpoch (d) -> Error.unexpected "[epochCRand] invoked on initial epoch."
    | SuccEpoch (cr,sr,si,pe) -> cr

let epochCSRands e =
    epochCRand e @| epochSRand e

type ConnectionInfo = {
    role: Role; // cached, could be retrieved from id_out
    id_rand: random; // our random
    id_in: epoch;
    id_out: epoch}

let connectionRole ci = ci.role

let initConnection role rand =
    let ctos = InitEpoch Client in
    let stoc = InitEpoch Server in
    match role with
    | Client -> {role = Client; id_rand = rand; id_in = stoc; id_out = ctos}
    | Server -> {role = Server; id_rand = rand; id_in = ctos; id_out = stoc}

let nextEpoch epoch crand srand si =
    SuccEpoch (crand, srand, si, epoch )

let predEpoch (e:epoch) = 
    match e with
    | SuccEpoch(_,_,_, e') -> e'
    | InitEpoch(r) -> failwith "no pred"

let rec epochWriter (e:epoch) =
    match e with
    | InitEpoch(r) -> r
    | SuccEpoch(_,_,_,_) -> 
        let pe = predEpoch e in
          epochWriter pe

// the tight index we use as an abstract parameter for StatefulAEAD et al
type id = { 
  msId   : msId;    
  kdfAlg : kdfAlg; 
  pv: ProtocolVersion; //Should be part of aeAlg 
  aeAlg  : aeAlg   
  csrConn: csrands;
  ext: negotiatedExtensions;
  writer : Role }

//let idInv (i:id):succEpoch = failwith "requires a log, and pointless to implement anyway"

let unAuthIdInv (i:id):epoch = 
#if verify
    failwith "only creates epochs for bad ids"
#else
    InitEpoch (i.writer)
#endif

let macAlg_of_id id = macAlg_of_aeAlg id.aeAlg
let encAlg_of_id id = encAlg_of_aeAlg id.aeAlg
let pv_of_id (id:id) =  id.pv //TODO MK fix
let kdfAlg_of_id (id:id) = id.kdfAlg

type event =
  | KeyCommit of    csrands * ProtocolVersion * aeAlg 
  | KeyGenClient of csrands * ProtocolVersion * aeAlg 
  | SentCCS of Role * epoch


let noId: id = { 
  msId = noMsId; 
  kdfAlg=(SSL_3p0,nullCipherSuite); 
  pv=SSL_3p0; 
  aeAlg= MACOnly(MA_SSLKHASH(NULL)); 
  csrConn = noCsr;
  ext = [];
  writer=Client }

let id e = 
  if isInitEpoch e 
  then noId 
  else
    let si     = epochSI e
    let cs     = si.cipher_suite
    let pv     = si.protocol_version
    let msi    = msi si
    let kdfAlg = kdfAlg si
    let aeAlg  = aeAlg cs pv
    let csr    = csrands si
    let ext    = si.extensions
    let wr     = epochWriter e
    { msId = msi; 
      kdfAlg = kdfAlg; 
      pv = pv; 
      aeAlg = aeAlg; 
      csrConn = csr;
      ext = ext;
      writer = wr }

// Pretty printing
let sinfo_to_string (si:SessionInfo) =
#if verify
    ""
#else
    let sb = new System.Text.StringBuilder() in
    let sb = sb.AppendLine("Session Information:") in
    let sb = sb.AppendLine(Printf.sprintf "Protocol Version: %A" si.protocol_version) in
    let sb = sb.AppendLine(Printf.sprintf "Ciphersuite: %A" (
                            match name_of_cipherSuite si.cipher_suite with
                            | Error.Error(_) -> failwith "Unknown ciphersuite"
                            | Error.Correct(c) -> c)) in
    let sb = sb.AppendLine(Printf.sprintf "Session ID: %s" (hexString si.sessionID)) in
    let sb = sb.AppendLine(Printf.sprintf "Session Hash: %s" (hexString si.session_hash)) in
    let sb = sb.AppendLine(Printf.sprintf "Server Identity: %s" (
                            match Cert.get_hint si.serverID with
                            | None -> "None"
                            | Some(c) -> c)) in
    let sb = sb.AppendLine(Printf.sprintf "Client Identity: %s" (
                            match Cert.get_hint si.clientID with
                            | None -> "None"
                            | Some(c) -> c)) in
    let sb = sb.AppendLine(Printf.sprintf "Extensions: %A" si.extensions) in
    sb.ToString()
#endif

// Application configuration
type helloReqPolicy =
    | HRPIgnore
    | HRPFull
    | HRPResume

type config = {
    minVer: ProtocolVersion
    maxVer: ProtocolVersion
    ciphersuites: cipherSuites
    compressions: Compression list

    (* Handshake specific options *)
   
    (* Client side *)
    honourHelloReq: helloReqPolicy
    allowAnonCipherSuite: bool
    safe_resumption: bool
    
    (* Server side *)
    request_client_certificate: bool
    check_client_version_in_pms_for_old_tls: bool

    (* Common *)
    safe_renegotiation: bool
    server_name: Cert.hint
    client_name: Cert.hint
            
    (* Sessions database *)
    sessionDBFileName: string
    sessionDBExpiry: TimeSpan
    }

let defaultConfig ={
    minVer = SSL_3p0
    maxVer = TLS_1p2
    ciphersuites = cipherSuites_of_nameList
                    [ TLS_RSA_WITH_AES_128_CBC_SHA;
                      TLS_RSA_WITH_3DES_EDE_CBC_SHA ]
    compressions = [ NullCompression ]

    honourHelloReq = HRPResume
    allowAnonCipherSuite = false
    request_client_certificate = false
    check_client_version_in_pms_for_old_tls = true
    
    safe_renegotiation = true
    safe_resumption = false // Turn to true if it gets standard
    server_name = "mitls.example.org"
    client_name = "client.example.org"

    sessionDBFileName = "sessionDBFile.bin"
    sessionDBExpiry = newTimeSpan 1 0 0 0 (*@ one day, as suggested by the RFC *)
    }

let max_TLSPlaintext_fragment_length = 16384 (*@ 2^14 *)
let max_TLSCompressed_fragment_length = max_TLSPlaintext_fragment_length + 1024
let max_TLSCipher_fragment_length = max_TLSCompressed_fragment_length + 1024
let fragmentLength = max_TLSPlaintext_fragment_length (*CF use e.g. 1 for testing *)

#if ideal

let honestPMS (pi:pmsId) : bool =
    match pi with
    | SomePmsId(PMS.RSAPMS(pk,cv,rsapms))   -> PMS.honestRSAPMS pk cv rsapms 
    | SomePmsId(PMS.DHPMS(p,g,gx,gy,dhpms)) -> PMS.honestDHPMS p g gx gy dhpms 
    | _ -> false

let strongCRE (ca:creAlg) = failwith "spec only": bool

// These functions are used only for specifying ideal implementations
let safeHS (e:epoch) = failwith "spec only": bool
let safeHS_SI (e:SessionInfo) = failwith "spec only": bool
let safeCRE (e:SessionInfo) = failwith "spec only": bool
let safeVD (e:SessionInfo) = failwith "spec only": bool
let auth (e:epoch) = failwith "spec only": bool
let safe (e:epoch) = failwith "spec only" : bool //CF Define in terms of strength and honesty

let safeKDF (i:id) = failwith "spec only": bool
let authId (i:id) = failwith "spec only":bool
let safeId  (i:id) = failwith "spec only":bool
#endif
