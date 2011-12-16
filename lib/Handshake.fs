module Handshake

open Bytes
open Record
open Error
open Formats
open HS_msg
open Algorithms
open CipherSuites
open TLSInfo
open TLSPlain
open AppCommon
open Principal
open SessionDB
open PRFs

/// Handshake state machines 

type clientSpecificState =
    { resumed_session: bool
      must_send_cert: certificateRequest Option
      client_certificate: (cert list) Option }

type clientState =
    | ServerHello
    | Certificate
    | ServerKeyExchange
    | CertReqOrSHDone
    | CSHDone of clientSpecificState
    | CCCS of clientSpecificState
    | CFinished of clientSpecificState
    | CWaitingToWrite
    | CIdle

type serverSpecificState =
    { resumed_session: bool
      highest_client_ver: ProtocolVersion}

type serverState =
    | ClientHello
    | ClCert of serverSpecificState
    | ClientKEX of serverSpecificState
    | CertificateVerify of serverSpecificState
    | SCCS of serverSpecificState
    | SFinished of serverSpecificState
    | SWaitingToWrite
    | SIdle

type protoState =
    | Client of clientState
    | Server of serverState

type pre_hs_state = {
  hs_outgoing    : bytes                  (* outgoing data before a ccs *)
  ccs_outgoing: (bytes * ccs_data) option (* marker telling there's a ccs ready *)
  hs_outgoing_after_ccs: bytes            (* data to be sent after the ccs has been sent *)
  hs_incoming    : bytes                  (* partial incoming HS message *)
  ccs_incoming: ccs_data option (* used to store the computed secrets for receiving data. Not set when receiving CCS, but when we compute the session secrects *)
  poptions: protocolOptions;
  pstate : protoState
  hs_msg_log: bytes
  hs_cur_info : SessionInfo; (* The session we're currrently running into *)
  cur_ms: masterSecret; (* The master secrect associated with the current session. *)
  hs_next_info: SessionInfo; (* The session we're establishing within the current HS *)
  next_ms: masterSecret; (* The ms we're establishing *)
  ki_crand: bytes; (* Client random for the session we're establishing (to be stored in KeyInfo) *)
  ki_srand: bytes; (* Current server random, as above *)
  hs_renegotiation_info_cVerifyData: bytes (*Renegotiation info associated with the session we're establishing *)
  hs_renegotiation_info_sVerifyData: bytes
}

type hs_state = pre_hs_state

type HSFragReply =
  | EmptyHSFrag
  | HSFrag of (int * fragment)
  | HSWriteSideFinished of (int * fragment)
  | HSFullyFinished_Write of (int * fragment) * StorableSession
  | CCSFrag of (int * fragment) * ccs_data

let next_fragment state =
    (* Assumptions: The buffers have been filled in the following order:
       1) hs_outgoing; 2) ccs_outgoing; 3) hs_outgoing_after_ccs
       hs_outgoing_after_ccs is filled all at once; so, when it's empty,
       we can conclude HS protocol is terminated, and no more data will be added to any buffer
       (until a re-handshake, which resets everything anyway) *)
    match state.hs_outgoing with
    | x when equalBytes x [||] ->
        match state.ccs_outgoing with
        | None ->
            match state.hs_outgoing_after_ccs with
            | x when equalBytes x [||] -> (EmptyHSFrag,state)
            | d ->
                (* Exceptionally, these fragments must be issued for the upcoming session info. Indeed, after sending CCS, we're
                   using the next_info, without knowing if it will be good or not *)
                let (f,rem) = pub_fragment state.hs_next_info d in
                let state = {state with hs_outgoing_after_ccs = rem} in
                match rem with
                | x when equalBytes x [||] ->
                    (* The logic of the next statement works like this:
                        If we (be either client or server) are in CCS state, it means we finished writing, but we still have to read
                        other side CCS and Finished messages, so issue a HSWriteSideFinished. If we're in Idle, it means the full
                        protocol completed, and we issue a HSFullyFinished *)
                    match state.pstate with
                    | Client (cstate) ->
                        (* Unfortunately, we cannot use the "resumed_session" flag of the client specific state, because there might
                           be no such client specific state available. So, according to the handshake state machine, we infer whether
                           we are doing full handshake or resumption. *)
                        match cstate with
                        | CCCS (_) -> (HSWriteSideFinished (f), state)
                        | CWaitingToWrite ->
                            let storable_session =
                                { sinfo = state.hs_next_info;
                                  ms = state.next_ms;
                                  dir = CtoS}
                            (HSFullyFinished_Write (f,storable_session), state)
                        | _ -> unexpectedError "[next_fragment] invoked in invalid state"
                    | Server (sstate) ->
                        match sstate with
                        | SCCS (_)->
                            (HSWriteSideFinished (f), state)
                        | SWaitingToWrite ->
                            let storable_session =
                                { sinfo = state.hs_next_info;
                                  ms = state.next_ms;
                                  dir = StoC}
                            (HSFullyFinished_Write (f,storable_session), state)
                        | _ -> unexpectedError "[next_fragment] invoked in invalid state"
                | _ -> (HSFrag(f),state)
        | Some data ->
            (* Resetting the ccs_outgoing buffer here is necessary for the current "next_fragment" logic to work.
               It should also be safe to loose the associated KeyInfo, because it has already been used to generate
               the Finished message on our side *)
            let state = {state with ccs_outgoing = None}
            let (ccs,ccs_data) = data in
            let (frag,_) = pub_fragment state.hs_cur_info ccs in
            (CCSFrag (frag,ccs_data), state)
    | d ->
        (* The fragment must be issued for the current session we're in, not the one we're establishing *)
        let (f,rem) = pub_fragment state.hs_cur_info d in
        let state = {state with hs_outgoing = rem} in
        (HSFrag(f),state)

type recv_reply = 
  | HSAck      (* fragment accepted, no visible effect so far *)
  | HSChangeVersion of Direction * ProtocolVersion 
                          (* ..., and we should use this new protocol version for sending *) 
  | HSReadSideFinished
  | HSFullyFinished_Read of StorableSession (* ..., and we can start sending data on the connection *)


/// Handshake message format 

// we need a precise spec, as verifyData is a sereis of such messages.
// private definition !ht,data. FragmentBytes(ht,data) = HTBytes(ht) @| VLBytes(3,data)

let makeFragment ht data = htbytes ht @| vlbytes 3 data 

let parseFragment state =
    (* Inefficient but simple implementation:
       every time we reparse the whole incoming buffer,
       searching for a full packet. When a full packet is found,
       it is removed from the buffer. *)
    if length state.hs_incoming < 4 then None (* not enough data to start parsing *)
    else
        let (hstypeb,rem) = split state.hs_incoming 1 in
        let (lenb,rem) = split rem 3 in
        let len = int_of_bytes lenb in
        if length rem < len then None (* not enough payload, try next time *)
        else
            let hstype = parseHT hstypeb in
            let (payload,rem) = split rem len in
            let state = { state with hs_incoming = rem } in
            let to_log = hstypeb @| lenb @| payload in
            Some(state,hstype,payload,to_log)

/// Hello Request 

let makeHelloRequestBytes () = makeFragment HT_hello_request [||]

/// Extensions [could inline from HS_msg] 

let makeExtStructBytes extType data =
    let extBytes = bytes_of_HExt extType in
    let payload = vlbytes 2 data in
    extBytes @| payload

let makeExtBytes data =  vlbytes 2 data

let makeRenegExtBytes verifyData =
    let payload = vlbytes 1 verifyData in
    makeExtStructBytes HExt_renegotiation_info payload

let rec extensionList_of_bytes_int data list =
    match length data with
    | 0 -> correct (list)
    | x when x > 0 && x < 4 ->
        (* This is a parsing error, or a malformed extension *)
        Error (HSError(AD_decode_error), HSSendAlert)
    | _ ->
        let (extTypeBytes,rem) = split data 2 in
        let extType = hExt_of_bytes extTypeBytes in
        match vlsplit 2 rem with
        | Error(x,y) -> Error (HSError(AD_decode_error), HSSendAlert) (* Parsing error *)
        | Correct (payload,rem) -> extensionList_of_bytes_int rem ([(extType,payload)] @ list)

let extensionList_of_bytes data =
    match length data with
    | 0 -> correct ([])
    | 1 -> Error(HSError(AD_decode_error),HSSendAlert)
    | _ ->
        match vlparse 2 data with
        | Error(x,y)    -> Error(HSError(AD_decode_error),HSSendAlert)
        | Correct(exts) -> extensionList_of_bytes_int exts []

let check_reneg_info payload expected =
    // We also check there were no more data in this extension.
    match vlparse 1 payload with
    | Error(x,y)     -> false
    | Correct (recv) -> equalBytes recv expected

let check_client_renegotiation_info cHello expected =
    match extensionList_of_bytes cHello.extensions with
    | Error(x,y) -> false
    | Correct(extList) ->
        (* Check there is at most one renegotiation_info extension *)
        let ren_ext_list = List.filter (fun (ext,_) -> ext = HExt_renegotiation_info) extList in
        if ren_ext_list.Length > 1 then
            false
        else
            let has_SCSV = contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV cHello.cipher_suites in
            if equalBytes expected [||] 
            then  
                (* First handshake *)
                if ren_ext_list.Length = 0 
                then has_SCSV
                    (* either client gave SCSV and no extension; this is OK for first handshake *)
                    (* or the client doesn't support this extension and we fail *)
                else
                    let ren_ext = ren_ext_list.Head in
                    let (extType,payload) = ren_ext in
                    check_reneg_info payload expected
            else
                (* Not first handshake *)
                if has_SCSV || (ren_ext_list.Length = 0) then false
                else
                    let ren_ext = ren_ext_list.Head in
                    let (extType,payload) = ren_ext in
                    check_reneg_info payload expected

let inspect_ServerHello_extensions recvExt expected =
    (* Code is ad-hoc for the only extension we support now: renegotiation_info *)
    match extensionList_of_bytes recvExt with
    | Error (x,y) -> Error (x,y)
    | Correct (extList) ->
        (* We expect to find exactly one extension *)
        match extList.Length with
        | 0 -> Error(HSError(AD_handshake_failure),HSSendAlert)
        | x when not (x = 1) -> Error(HSError(AD_unsupported_extension),HSSendAlert)
        | _ ->
            let (extType,payload) = extList.Head in
            match extType with
            | HExt_renegotiation_info ->
                (* Check its content *)
                if check_reneg_info payload expected then
                    let unitVal = () in
                    correct (unitVal)
                else
                    (* RFC 5746, sec 3.4: send a handshake failure alert *)
                    Error(HSError(AD_handshake_failure),HSSendAlert)
            | _ -> Error(HSError(AD_unsupported_extension),HSSendAlert)


/// Client and Server random values

let makeTimestamp () = (* FIXME: we may need to abstract this function *)
    let t = (System.DateTime.UtcNow - new System.DateTime(1970, 1, 1))
    (int) t.TotalSeconds

let makeRandom() = { time = makeTimestamp (); rnd = mkRandom 28}
let randomBytes r = bytes_of_int 4 r.time @| r.rnd
let parseRandom data = 
    // Length(data)=32 
    let (tb,b) = split data 4 
    { time = int_of_bytes tb; rnd = b }

/// Compression algorithms 

let rec compressionMethodsBytes cs =
   match cs with
   | c::cs -> compressionBytes c @| compressionMethodsBytes cs
   | []    -> [||] 

/// Client Hello 

// ClientHelloBytes(clVer,clRdm,sid,clientCipherSuites,cm,extensions) = 
// VersionBytes clVer @| CRBytes clRdm @| SidBytes sid 
//     @| CipherSuitesBytes clientCipherSuites 
//     @| CompressionsBytes cm @| extensions

let parseClientHello data =
    // pre: Length(data) > 34
    // correct post: something like data = ClientHelloBytes(...) 
    let (clVerBytes,clRandomBytes,data) = split2 data 2 32 in
    let cv = parseVersion clVerBytes
    let cr = parseRandom clRandomBytes
    match vlsplit 1 data with
    | Error(x,y) -> Error(x,y)
    | Correct (sid,data) ->
    match vlsplit 2 data with
    | Error(x,y) -> Error(x,y)
    | Correct (clCiphsuitesBytes,data) ->
    match parseCipherSuites clCiphsuitesBytes with
    | Error(x,y) -> Error(x,y) 
    | Correct(clientCipherSuites) ->
    match vlsplit 1 data with
    | Error(x,y) -> Error(x,y)
    | Correct (cmBytes,extensions) ->
    let cm = parseCompressions cmBytes
    correct(
     { client_version      = cv 
       ch_random           = cr 
       ch_session_id       = sid
       cipher_suites       = clientCipherSuites
       compression_methods = cm 
       extensions          = extensions},
     clRandomBytes
    )

// called only just below; inline? HS_msg.clientHello seem unhelpful
let makeClientHello poptions session prevCVerifyData =
    let ext =
        if poptions.safe_renegotiation 
        then makeExtBytes (makeRenegExtBytes prevCVerifyData)
        else [||]
    { client_version = poptions.maxVer
      ch_random = makeRandom()
      ch_session_id = session
      cipher_suites = poptions.ciphersuites
      compression_methods = poptions.compressions
      extensions = ext }

let makeClientHelloBytes poptions session cVerifyData =
    let cHello     = makeClientHello poptions session cVerifyData in
    let cVerB      = versionBytes cHello.client_version in
    let random     = randomBytes cHello.ch_random in
    let csessB     = vlbytes 1 cHello.ch_session_id in
    let ccsuitesB  = vlbytes 2 (bytes_of_cipherSuites cHello.cipher_suites)
    let ccompmethB = vlbytes 1 (compressionMethodsBytes cHello.compression_methods) 
    let data = cVerB @| random @| csessB @| ccsuitesB @| ccompmethB @| cHello.extensions in
    (makeFragment HT_client_hello data,random)

/// Server Hello 

let makeServerHelloBytes poptions sinfo prevVerifData =
    let verB = versionBytes sinfo.protocol_version in
    let sRandom = randomBytes (makeRandom()) in
    let sidB = vlbytes 1 (match sinfo.sessionID with
                          | None -> [||]
                          | Some(sid) -> sid)
    let csB = cipherSuiteBytes sinfo.cipher_suite in
    let cmB = compressionBytes sinfo.compression in
    let ext =
        if poptions.safe_renegotiation then
            let ren_extB = makeRenegExtBytes prevVerifData in
            makeExtBytes ren_extB
        else
            [||]
    let data = verB @| sRandom @| sidB @| csB @| cmB @| ext in
    (makeFragment HT_server_hello data,sRandom)

let parseServerHello data =
    let (serverVerBytes,serverRandomBytes,data) = split2 data 2 32 
    let serverVer = parseVersion serverVerBytes 
    match vlsplit 1 data with
    | Error(x,y) -> Error (x,y)
    | Correct (sid,data) ->
    let (csBytes,cmBytes,data) = split2 data 2 1 
    let cs = cipherSuite_of_bytes csBytes //TODO we should fail here if cs is "unknown"
    let cm = compression_of_bytes cmBytes 
    let r = 
     { server_version = serverVer
       sh_random = parseRandom serverRandomBytes
       sh_session_id = sid
       cipher_suite = cs
       compression_method = cm
       neg_extensions = data}
    correct(r,serverRandomBytes)


(* Obsolete. Use PRFs.prfMS instead *)
(*
let compute_master_secret pms version crandom srandom = 
    match version with 
    | ProtocolVersion.SSL_3p0 ->
        match ssl_prf pms (append crandom srandom) 48 with
        | Error(x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
        | Correct (res) -> correct (res)
    | x when x = ProtocolVersion.TLS_1p0 || x = ProtocolVersion.TLS_1p1 ->
        match prf pms "master secret" (append crandom srandom) 48 with
        | Error(x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
        | Correct (res) -> correct (res)
    | ProtocolVersion.TLS_1p2 ->
        match tls12prf pms "master secret" (append crandom srandom) 48 with
        | Error(x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
        | Correct (res) -> correct (res)
    | _ -> Error(HSError(AD_internal_error),HSSendAlert)
*)

/// Certificates and Certificate Requests

// CertificateListBytes([]) = [||] 
// CertificateListBytes(c::cs) = CertificateBytes(c) @| CertificateListBytes(cs)
// CertificatesBytes(cs) = VLBytes 3 (CertificateListBytes(cs))
 
let certificatesBytes certList =
    vlbytes 3 (List.foldBack (fun c a -> vlbytes 3 (certificateBytes c) @| a) certList [||])
    
let makeCertificateBytes cso =
    let cs = match cso with None -> [] | Some(cs) -> cs
    makeFragment HT_certificate (certificatesBytes cs)

// we need something more general for parsing lists, e.g.
let rec parseList parseOne b =
    if length b = 0 then correct([])
    else 
    match parseOne b with
    | Correct(x,b) -> 
        match parseList parseOne b with 
        | Correct(xs) -> correct(x::xs)
        | Error(x,y)  -> Error(x,y)
    | Error(x,y)      -> Error(x,y)

let parseOneCertificate b = 
    match vlsplit 3 b with 
    | Correct (one,rest) ->
        match certificate_of_bytes one with
        | Correct(c) -> Correct(c,rest) 
        | Error(x,y) -> Error(HSError(AD_bad_certificate),HSSendAlert)
    | Error(x,y)     -> Error(HSError(AD_bad_certificate),HSSendAlert)
// then call 
// parseList parseOneCerticate b instead of 
// parseCertificate_int b []

let rec parseCertificate_int toProcess list =
    if equalBytes toProcess [||] then
        correct(list)
    else
        match vlsplit 3 toProcess with
        | Error(x,y) -> Error(HSError(AD_bad_certificate),HSSendAlert)
        | Correct (nextCertBytes,toProcess) ->
        match certificate_of_bytes nextCertBytes with
        | Error(x,y) -> Error(HSError(AD_bad_certificate),HSSendAlert)
        | Correct(nextCert) ->
            let list = list @ [nextCert] in
            parseCertificate_int toProcess list

let parseCertificate data =
    match vlsplit 3 data with
    | Error(x,y) -> Error(HSError(AD_bad_certificate),HSSendAlert)
    | Correct (certList,_) ->
    //CF why ignoring the rest? This breaks VerifyData
    match parseCertificate_int certList [] with
    | Error(x,y) -> Error(x,y)
    | Correct(certList) -> correct({certificate_list = certList})

//CF This list used to be reversed; was it intented??
//   Also, we do not currently enforce that the bytes are between 0 and 3.
let rec parseCertificateTypeList data =
    if length data = 0 then []
    else
        let (thisByte,data) = split data 1 in
        thisByte :: parseCertificateTypeList data 

let rec sigAlgsList_of_bytes data res =
    if length data > 2 then
        let (thisFieldBytes,data) = split data 2 in
        let (thisHashB,thisSigB) = split thisFieldBytes 1 in
        let thisHash = int_of_bytes thisHashB in
        match tls12enum_to_hashAlg thisHash with
        | Some (hash) ->
            let thisSig = int_of_bytes thisSigB in
            let thisField = {SaHA_hash = hash; SaHA_signature = enum<SigAlg>thisSig} in
            let res = [thisField] @ res in
            sigAlgsList_of_bytes data res
        | None -> Error(HSError(AD_illegal_parameter),HSSendAlert)
    else
        let (thisHashB,thisSigB) = split data 1 in
        let thisHash = int_of_bytes thisHashB in
        match tls12enum_to_hashAlg thisHash with
        | Some(hash) ->
            let thisSig = int_of_bytes thisSigB in
            let thisField = {SaHA_hash = hash; SaHA_signature = enum<SigAlg>thisSig} in
            correct ([thisField] @ res)
        | None -> Error(HSError(AD_illegal_parameter),HSSendAlert)

let rec distNamesList_of_bytes data res =
    if length data = 0 then
        correct (res)
    else
        if length data < 2 then (* FIXME: maybe at least 3 bytes, because we don't want empty names... *)
            Error(Parsing,CheckFailed)
        else
            match vlsplit 2 data with
            | Error(x,y) -> Error(x,y)
            | Correct (nameBytes,data) ->
            let name = iutf8 nameBytes in (* FIXME: I have no idea wat "X501 represented in DER-encoding format" (RFC 5246, page 54) is. I assume UTF8 will do. *)
            let res = [name] @ res in
            distNamesList_of_bytes data res

let makeCertificateRequestBytes cs version =
    (* TODO: now we send all possible choices, including inconsistent ones, and we hope the client will pick the proper one. *)
    let certTypes = vlbytes 1 (CLT_RSA_Sign @| CLT_DSS_Sign @| CLT_RSA_Fixed_DH @| CLT_DSS_Fixed_DH) 
    let sigAndAlg =
        match version with
        | ProtocolVersion.TLS_1p2 ->
            (* For no particular reason, we will offer rsa-sha1 and dsa-sha1 *)
            let rsaSigB = bytes_of_int 1 (int SigAlg.SA_rsa) in
            let dsaSigB = bytes_of_int 1 (int SigAlg.SA_dsa) in
            let sha1B   = bytes_of_int 1 (hashAlg_to_tls12enum Algorithms.hashAlg.SHA) in
            let sigAndAlg = sha1B @| rsaSigB @| sha1B @| dsaSigB in
            vlbytes 2 sigAndAlg
        | v when v >= ProtocolVersion.SSL_3p0 -> [||]
        | _ -> unexpectedError "[makeCertificateRequestBytes] invoked on unknown protocol version."
    (* We specify no cert auth *)
    let distNames = vlbytes 2 [||] in
    let data = certTypes @| sigAndAlg @| distNames in
    makeFragment HT_certificate_request data

let parseCertificateRequest version data =
    match vlsplit 1 data with
    | Error(x,y) -> Error(HSError(AD_illegal_parameter),HSSendAlert)
    | Correct (certTypeListBytes,data) ->
    let certTypeList = parseCertificateTypeList certTypeListBytes in
    let sigAlgsAndData = (
        if version = ProtocolVersion.TLS_1p2 then
            match vlsplit 2 data with
            | Error(x,y) -> Error(HSError(AD_illegal_parameter),HSSendAlert)
            | Correct (sigAlgsBytes,data) ->
            match sigAlgsList_of_bytes sigAlgsBytes [] with
            | Error(x,y) -> Error(x,y)
            | Correct (sigAlgsList) ->
                correct (Some(sigAlgsList),data)
        else
            correct (None,data)) in
    match sigAlgsAndData with
    | Error(x,y) -> Error(x,y)
    | Correct ((sigAlgs,data)) ->
    match vlsplit 2 data with
    | Error(x,y) -> Error(HSError(AD_illegal_parameter),HSSendAlert)
    | Correct  (distNamesBytes,_) ->
    match distNamesList_of_bytes distNamesBytes [] with
    | Error(x,y) -> Error(HSError(AD_illegal_parameter),HSSendAlert)
    | Correct distNamesList ->
    let res = { client_certificate_type = certTypeList;
                signature_and_hash_algorithm = sigAlgs;
                certificate_authorities = distNamesList} in
    correct (res)

/// 

let makeServerHelloDoneBytes unitVal =
    makeFragment HT_server_hello_done [||]

let makeClientKEXBytes state clSpecInfo =
    if canEncryptPMS state.hs_next_info.cipher_suite then
        let pms = genPMS state.hs_next_info state.poptions.maxVer in
        match state.hs_next_info.serverID with
        | None -> unexpectedError "[makeClientKEXBytes] Server certificate should always be present with a RSA signing cipher suite."
        | Some (serverCert) ->
            let pubKey = pubKey_of_certificate serverCert in
            match rsaEncryptPMS pubKey pms with
            | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
            | Correct (encpms) ->
                if state.hs_next_info.protocol_version = ProtocolVersion.SSL_3p0 then
                    correct ((makeFragment HT_client_key_exchange encpms),pms)
                else
                    let encpms = vlbytes 2 encpms in
                    correct ((makeFragment HT_client_key_exchange encpms),pms)
    else
        match clSpecInfo.must_send_cert with
        | Some (_) ->
            match state.hs_next_info.clientID with
            | None -> (* Client certificate not sent, (and not in RSA mode)
                         so we must use DH parameters *)
                (* TODO: send public Yc value *)
                let ycBytes = [||] in
                (* TODO: compute pms *)
                let pms = empty_pms in
                correct ((makeFragment HT_client_key_exchange ycBytes),pms)
            | Some (cert) ->
                (* TODO: check whether the certificate already contained suitable DH parameters *)
                let pms = empty_pms in
                correct ((makeFragment HT_client_key_exchange [||]),pms)
        | None ->
            (* Use DH parameters *)
            let ycBytes = [||] in
            let pms = empty_pms in
            correct ((makeFragment HT_client_key_exchange ycBytes),pms)

(* Obsolete *)
(*
let hashNametoFun hn =
    match hn with
    | HashAlg.HA_md5 -> correct (md5)
    | HashAlg.HA_sha1 -> correct (sha1)
    | HashAlg.HA_sha224 -> Error(HSError(AD_internal_error),HSSendAlert)
    | HashAlg.HA_sha256 -> correct (sha256)
    | HashAlg.HA_sha384 -> correct (sha384)
    | HashAlg.HA_sha512 -> correct (sha512)
    | _ -> Error(HSError(AD_internal_error),HSSendAlert)
*)

let makeCertificateVerifyBytes cert data pv certReqMsg=
    let priKey = priKey_of_certificate cert in
    match pv with
    | ProtocolVersion.TLS_1p2 ->
        (* If DSA, use SHA-1 hash *)
        if certificate_is_dsa cert then (* TODO *)
            (*let hash = sha1 data in
            let signed = dsa_sign priKey hash in *)
            correct ([||])
        else
            (* Get server preferred hash algorithm *)
            let hashAlg =
                match certReqMsg.signature_and_hash_algorithm with
                | None -> unexpectedError "[makeCertificateVerifyBytes] We are in TLS 1.2, so the server should send a SigAndHashAlg structure."
                | Some (sahaList) -> sahaList.Head.SaHA_hash
            let hashed = HASH.hash hashAlg data in
            match RSA.rsaEncrypt priKey hashed with
            | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
            | Correct (signed) ->
                let signed = vlbytes 2 signed in
                let hashAlgBytes = bytes_of_int 1 (hashAlg_to_tls12enum hashAlg) in
                let signAlgBytes = bytes_of_int 1 (int SigAlg.SA_rsa) in
                let payload = hashAlgBytes @| signAlgBytes @| signed in
                correct (makeFragment HT_certificate_verify payload)
    | x when x = ProtocolVersion.TLS_1p0 || x = ProtocolVersion.TLS_1p1 ->
        (* TODO *) Error(HSError(AD_internal_error),HSSendAlert)
    | ProtocolVersion.SSL_3p0 ->
        (* TODO *) Error(HSError(AD_internal_error),HSSendAlert)
    | _ -> Error(HSError(AD_internal_error),HSSendAlert)

let CCSBytes = [| 1uy |] 

(* Obsolete. Use PRFs.prfKeyExp instead *)
(*
let expand_master_secret version ms crandom srandom nb = 
  match version with 
  | ProtocolVersion.SSL_3p0 -> 
     match ssl_prf ms (append srandom crandom) nb with
     | Error(x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
     | Correct (res) -> correct (res)
  | x when x = ProtocolVersion.TLS_1p0 || x = ProtocolVersion.TLS_1p1 ->
     match prf ms "key expansion" (append srandom crandom) nb with
     | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
     | Correct (res) -> correct(res)
  | ProtocolVersion.TLS_1p2 ->
     match tls12prf ms "key expansion" (append srandom crandom) nb with
     | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
     | Correct (res) -> correct (res)
  | _ -> Error(HSError(AD_internal_error),HSSendAlert)
*)

(*
let split_key_block key_block hsize ksize ivsize = 
  let cmk = Array.sub key_block 0 hsize in
  let smk = Array.sub key_block hsize hsize in
  let cek = Array.sub key_block (2*hsize) ksize in
  let sek = Array.sub key_block (2*hsize+ksize) ksize in
  let civ = Array.sub key_block (2*hsize+2*ksize) ivsize in
  let siv = Array.sub key_block (2*hsize+2*ksize+ivsize) ivsize in
  (cmk,smk,cek,sek,civ,siv)
*)

let generateKeys (outKi:KeyInfo) (inKi:KeyInfo) (ms:masterSecret) =
    let key_block = prfKeyExp outKi ms in
    let (cmk,smk,cek,sek,civ,siv) = splitKeys outKi inKi key_block in
    match outKi.dir with 
        | CtoS -> smk,sek,siv,cmk,cek,civ
        | StoC -> cmk,cek,civ,smk,sek,siv

(* Obsolete. Use PRFs.prfVerifyData instead *)
(*
let bldVerifyData version cs ms entity hsmsgs = 
  (* FIXME: There should be only one (verifyData)prf function in CryptoTLS, that takes
     version and cs and performs the proper computation *)
  match version with 
  | ProtocolVersion.SSL_3p0 ->
    let ssl_sender = 
        match entity with
        | CtoS -> ssl_sender_client 
        | StoC -> ssl_sender_server
    let mm = append hsmsgs (append ssl_sender ms) in
    match md5 (append mm ssl_pad1_md5) with
    | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
    | Correct (inner_md5) ->
        match md5 (append ms (append ssl_pad2_md5 (inner_md5))) with
        | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
        | Correct (outer_md5) ->
            match sha1 (append mm ssl_pad1_sha1) with
            | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
            | Correct(inner_sha1) ->
                match sha1 (append ms (append ssl_pad2_sha1 (inner_sha1))) with
                | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
                | Correct (outer_sha1) ->
                    correct (append outer_md5 outer_sha1)
  | x when x = ProtocolVersion.TLS_1p0 || x = ProtocolVersion.TLS_1p1 -> 
    let tls_label = 
        match entity with
        | CtoS -> "client finished"
        | StoC -> "server finished"
    match md5 hsmsgs with
    | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
    | Correct (md5hash) ->
        match sha1 hsmsgs with
        | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
        | Correct (sha1hash) ->
            match prf ms tls_label (append md5hash sha1hash) 12 with
            | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
            | Correct (result) -> correct (result)
  | ProtocolVersion.TLS_1p2 ->
    let tls_label = 
        match entity with
        | CtoS -> "client finished"
        | StoC -> "server finished"
    let verifyDataHashAlg = verifyDataHashAlg_of_ciphersuite cs in
    match verifyDataHashFun hsmsgs with
    | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
    | Correct(hashResult) ->
        let verifyDataLen = verifyDataLen_of_ciphersuite cs in
        match tls12prf ms tls_label hashResult verifyDataLen with
        | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
        | Correct(result) -> correct (result)
  | _ -> Error(HSError(AD_internal_error),HSSendAlert)
*)

(* Probably we want to move the two following functions into PRFs *)
let checkVerifyData ki ms hsmsgs orig =
    let computed = prfVerifyData ki ms hsmsgs in
    equalBytes orig computed

let makeFinishedMsgBytes ki ms hsmsgs =
    let payload = prfVerifyData ki ms hsmsgs in
    ((makeFragment HT_finished payload), payload)

(*
let ciphstate_of_ciphtype ct key iv =
    match ct with
    | CT_block -> BlockCipherState (key,iv)
    | CT_stream -> StreamCipherState
*)

    

let find_client_cert (certReqMsg:certificateRequest) : (cert list) option =
    (* TODO *) None

let parseClientKEX sinfo sSpecState pops data =
    if canEncryptPMS sinfo.cipher_suite then
        match sinfo.serverID with
        | Some(cert) ->
            let encrypted = (* parse the message *)
                match sinfo.protocol_version with
                | ProtocolVersion.SSL_3p0 -> correct (data)
                | v when v >= ProtocolVersion.TLS_1p0 ->
                        match vlparse 2 data with
                        | Correct (encPMS) -> correct(encPMS)
                        | Error(x,y) -> Error(HSError(AD_decode_error),HSSendAlert)
                | _                  -> Error(HSError(AD_internal_error),HSSendAlert)
            match encrypted with
            | Correct(encPMS) ->
                let res = getPMS sinfo sSpecState.highest_client_ver pops.check_client_version_in_pms_for_old_tls cert encPMS in
                correct(res)
            | Error(x,y) -> Error(x,y)
        | None -> unexpectedError "[parseClientKEX] when the ciphersuite can encrypt the PMS, the server certificate should always be set"
    else
        (* TODO *)
        (* We should support the DH key exchanges *)
        Error(HSError(AD_internal_error),HSSendAlert)

let certificateVerifyCheck (state:hs_state) (payload:bytes) =
    (* TODO: pretend client sent valid verification data. We need to understand how to treat certificates and related algorithms properly *)
    correct(true)

let compute_session_secrets_and_CCSs state dir =
    (* Create KeyInfos for both directions *)
    let outKi = { sinfo = state.hs_next_info;
                  dir = dir;
                  crand = state.ki_crand;
                  srand = state.ki_srand;
                }
    let inKi = { sinfo = state.hs_next_info;
                 dir = dualDirection dir;
                 crand = state.ki_crand;
                 srand = state.ki_srand;
                }
    let allKeys = generateKeys outKi inKi state.next_ms in
    let (rmk,rek,riv,wmk,wek,wiv) = allKeys in
    (* TODO: Add support for AEAD ciphers *)
    let readKey = RecordAEADKey (AEAD.MtE (rmk,rek)) in
    let readIV = if PVRequiresExplicitIV outKi.sinfo.protocol_version then ENC.iv3.NoIV () else ENC.iv3.SomeIV (riv) in
    let read_ccs_data = { ki = inKi
                          key = readKey
                          iv3 = readIV}
    let writeKey = RecordAEADKey (AEAD.MtE (wmk,wek)) in
    let writeIV = if PVRequiresExplicitIV outKi.sinfo.protocol_version then ENC.iv3.NoIV () else ENC.iv3.SomeIV (wiv) in
    let write_ccs_data = { ki = outKi
                           key = writeKey
                           iv3 = writeIV}
    (* Put the ccs_data in the appropriate buffers. *)
    let state = {state with ccs_outgoing = Some((CCSBytes,write_ccs_data))
                            ccs_incoming = Some(read_ccs_data)} in
    state

let prepare_client_output_full state clSpecState =
    let clientCertBytes =
        match clSpecState.must_send_cert with
        | Some (_) ->
            makeCertificateBytes clSpecState.client_certificate
        | None ->
            [||]

    match makeClientKEXBytes state clSpecState with
    | Error (x,y) -> Error (x,y)
    | Correct (result) ->
        let (clientKEXBytes,pms) = result in
        let ms = prfMS state.hs_next_info pms in
        (* Assert: state.hs_next_info.{c,s}rand = state.ki_{c,s}rand
           In fact, we want to use the {c,s}rand just used in this session (and not the constant sinfo ones).
           And indeed, the PMS is computed only during the first session
           where the assertion must be true. *)
        (* Original code:
        match compute_master_secret pms sinfo.more_info.mi_protocol_version state.hs_client_random state.hs_server_random with *)
        (* TODO: here we should shred pms *)
        let state = {state with next_ms = ms} in
        let certificateVerifyBytesResult =
            match state.hs_next_info.clientID with
            | None ->
                (* No client certificate ==> no certificateVerify message *)
                correct ([||])
            | Some (cert) ->
                if certificate_has_signing_capability cert then
                    let to_sign = state.hs_msg_log @| clientCertBytes @| clientKEXBytes in
                    match clSpecState.must_send_cert with
                    | None -> unexpectedError "[prepare_output] If client sent a certificate, it must have been requested to."
                    | Some (certReqMsg) ->
                        makeCertificateVerifyBytes cert to_sign state.hs_next_info.protocol_version certReqMsg
                else
                    correct ([||])
        match certificateVerifyBytesResult with
        | Error (x,y) -> Error (x,y)
        | Correct (certificateVerifyBytes) ->
            (* Enqueue current messages *)
            let to_send = clientCertBytes @| clientKEXBytes @| certificateVerifyBytes in
            let new_outgoing = state.hs_outgoing @| to_send in
            let new_log = state.hs_msg_log @| to_send in
            let state = {state with hs_outgoing = new_outgoing
                                    hs_msg_log  = new_log} in

            (* Handle CCS and Finished, including computation of session secrets *)
            let state = compute_session_secrets_and_CCSs state CtoS in
            (* Now go for the creation of the Finished message *)
            let ki = 
                match state.ccs_outgoing with
                | None -> unexpectedError "[prepare_client_output_full] The current state should contain a valid outgoing KeyInfo"
                | Some (_,ccs_data) -> ccs_data.ki
            let (finishedBytes,cVerifyData) = makeFinishedMsgBytes ki state.next_ms state.hs_msg_log in
            (* match makeFinishedMsgBytes sinfo.protocol_version sinfo.cipher_suite sinfo.more_info.mi_ms CtoS state.hs_msg_log with *)
            let new_out = state.hs_outgoing_after_ccs @| finishedBytes in
            let new_log = state.hs_msg_log @| finishedBytes in
            let state = {state with hs_outgoing_after_ccs = new_out
                                    hs_msg_log = new_log
                                    hs_renegotiation_info_cVerifyData = cVerifyData} in
            correct (state)

let prepare_client_output_resumption state =
    let ki = 
        match state.ccs_outgoing with
        | None -> unexpectedError "[prepare_client_output_resumption] The current state should contain a valid outgoing KeyInfo"
        | Some (_,ccs_data) -> ccs_data.ki
    let (finishedBytes,cVerifyData) = makeFinishedMsgBytes ki state.next_ms state.hs_msg_log in
    (* match makeFinishedMsgBytes sinfo.protocol_version sinfo.cipher_suite sinfo.more_info.mi_ms CtoS state.hs_msg_log with *)
    let new_out = state.hs_outgoing_after_ccs @| finishedBytes in
    (* No need to log this message *)
    let state = {state with hs_outgoing_after_ccs = new_out
                            hs_renegotiation_info_cVerifyData = cVerifyData} in
    state

let init_handshake dir poptions =
    (* Start a new first session without resumption *)
    match dir with
    | CtoS ->
        let (cHelloBytes,client_random) = makeClientHelloBytes poptions [||] [||] in
        let next_sinfo = {init_sessionInfo with init_crand = client_random} in
        {hs_outgoing = cHelloBytes
         ccs_outgoing = None
         hs_outgoing_after_ccs = [||]
         hs_incoming = [||]
         ccs_incoming = None
         poptions = poptions
         pstate = Client (ServerHello)
         hs_msg_log = cHelloBytes
         hs_cur_info = init_sessionInfo
         cur_ms = empty_masterSecret
         hs_next_info = next_sinfo
         next_ms = empty_masterSecret
         ki_crand = client_random
         ki_srand = [||]
         hs_renegotiation_info_cVerifyData = [||]
         hs_renegotiation_info_sVerifyData = [||]}
    | StoC ->
        {hs_outgoing = [||]
         ccs_outgoing = None
         hs_outgoing_after_ccs = [||]
         hs_incoming = [||]
         ccs_incoming = None
         poptions = poptions
         pstate = Server (ClientHello)
         hs_msg_log = [||]
         hs_cur_info = init_sessionInfo
         cur_ms = empty_masterSecret
         hs_next_info = init_sessionInfo
         next_ms = empty_masterSecret
         ki_crand = [||]
         ki_srand = [||]
         hs_renegotiation_info_cVerifyData = [||]
         hs_renegotiation_info_sVerifyData = [||]}

let resume_handshake sinfo ms poptions =
    (* Resume a session, for the first time in this connection.
       Set up our state as a client. Servers cannot resume *)
    match sinfo.sessionID with
    | None -> unexpectedError "[resume_handshake] a resumed session should always have a valid sessionID"
    | Some(sid) ->
    let (cHelloBytes,client_random) = makeClientHelloBytes poptions sid [||] in
    let state = {hs_outgoing = cHelloBytes
                 ccs_outgoing = None
                 hs_outgoing_after_ccs = [||]
                 hs_incoming = [||]
                 ccs_incoming = None
                 poptions = poptions
                 pstate = Client (ServerHello)
                 hs_msg_log = cHelloBytes
                 hs_cur_info = init_sessionInfo
                 cur_ms = empty_masterSecret
                 hs_next_info = sinfo
                 next_ms = ms
                 ki_crand = client_random
                 ki_srand = [||]
                 hs_renegotiation_info_cVerifyData = [||]
                 hs_renegotiation_info_sVerifyData = [||]} in
    state

let start_rehandshake (state:hs_state) (ops:protocolOptions) =
    (* Start a non-resuming handshake, over an existing connection.
       Only client side, since a server can only issue a HelloRequest *)
    match state.pstate with
    | Client (cstate) ->
        match cstate with
        | CIdle ->
            let (cHelloBytes,client_random) = makeClientHelloBytes ops [||] state.hs_renegotiation_info_cVerifyData in
            let next_sinfo = {init_sessionInfo with init_crand = client_random} in
            let state = {hs_outgoing = cHelloBytes
                         ccs_outgoing = None
                         hs_outgoing_after_ccs = [||]
                         hs_incoming = [||]
                         ccs_incoming = None
                         poptions = ops
                         pstate = Client (ServerHello)
                         hs_msg_log = cHelloBytes
                         hs_cur_info = state.hs_cur_info
                         cur_ms = state.cur_ms
                         hs_next_info = next_sinfo
                         next_ms = empty_masterSecret
                         ki_crand = client_random
                         ki_srand = [||]
                         hs_renegotiation_info_cVerifyData = state.hs_renegotiation_info_cVerifyData
                         hs_renegotiation_info_sVerifyData = state.hs_renegotiation_info_sVerifyData} in
            state
        | _ -> (* handshake already happening, ignore this request *)
            state
    | Server (_) -> unexpectedError "[start_rehandshake] should only be invoked on client side connections."

let start_rekey (state:hs_state) (ops:protocolOptions) =
    (* Start a (possibly) resuming handshake over an existing connection *)
    let sidOp = state.hs_cur_info.sessionID in
    match sidOp with
    | None -> unexpectedError "[start_rekey] must be invoked on a resumable session (that is, with a non-null session ID)."
    | Some (sid) ->
        (* FIXME: the following SessionDB interaction should be in dispatcher.
           But it cannot, because we can start re-keying from inside the HS, when we receive a
           ServerHelloRequest and a re-key policy. *)
        (* Ensure the sid is in the SessionDB *)
        match select ops sid with
        | None -> unexpectedError "[start_rekey] requested session expired or never stored in DB"
        | Some (retrievedSinfo) ->
            (* check the retrieved sinfo is compatible *)
            if not (state.hs_cur_info = retrievedSinfo.sinfo) || not (state.cur_ms = retrievedSinfo.ms) || not (retrievedSinfo.dir = CtoS) then
                unexpectedError "[start_rekey] Retrieved session is incompabitle"
            else
                match state.pstate with
                | Client (cstate) ->
                    match cstate with
                    | CIdle ->
                        let (cHelloBytes,client_random) = makeClientHelloBytes ops sid state.hs_renegotiation_info_cVerifyData in
                        let state = {hs_outgoing = cHelloBytes
                                     ccs_outgoing = None
                                     hs_outgoing_after_ccs = [||]
                                     hs_incoming = [||]
                                     ccs_incoming = None
                                     poptions = ops
                                     pstate = Client (ServerHello)
                                     hs_msg_log = cHelloBytes
                                     hs_cur_info = state.hs_cur_info
                                     cur_ms = state.cur_ms 
                                     hs_next_info = state.hs_cur_info
                                     next_ms = state.cur_ms                                   
                                     ki_crand = client_random
                                     ki_srand = [||]
                                     hs_renegotiation_info_cVerifyData = state.hs_renegotiation_info_cVerifyData
                                     hs_renegotiation_info_sVerifyData = state.hs_renegotiation_info_sVerifyData} in
                        state
                    | _ -> (* Handshake already ongoing, ignore this request *)
                        state
                | Server (_) -> unexpectedError "[start_rekey] should only be invoked on client side connections."

let start_hs_request (state:hs_state) (ops:protocolOptions) =
    match state.pstate with
    | Client _ -> unexpectedError "[start_hs_request] should only be invoked on server side connections."
    | Server (sstate) ->
        match sstate with
        | SIdle ->
            (* Put HelloRequest in outgoing buffer (and do not log it), and move to the ClientHello state (so that we don't send HelloRequest again) *)
            let new_out = state.hs_outgoing @| (makeHelloRequestBytes ()) in
            {state with hs_outgoing = new_out
                        poptions = ops
                        pstate = Server(ClientHello)}
        | _ -> (* Handshake already ongoing, ignore this request *)
            state

let new_session_idle state new_info ms =
    match state.pstate with
    | Client (_) ->
        {hs_outgoing = [||];
         ccs_outgoing = None;
         hs_outgoing_after_ccs = [||];
         hs_incoming = [||];
         ccs_incoming = None
         poptions = state.poptions;
         pstate = Client(CIdle);
         hs_msg_log = [||]
         hs_cur_info = new_info; (* Assert: This is in fact the current state.hs_next_info; same for ms *)
         cur_ms = ms;
         hs_next_info = init_sessionInfo
         next_ms = empty_masterSecret
         ki_crand = [||]
         ki_srand = [||]
         hs_renegotiation_info_cVerifyData = state.hs_renegotiation_info_cVerifyData
         hs_renegotiation_info_sVerifyData = state.hs_renegotiation_info_sVerifyData}
    | Server (_) ->
        {hs_outgoing = [||];
         ccs_outgoing = None;
         hs_outgoing_after_ccs = [||];
         hs_incoming = [||];
         ccs_incoming = None
         poptions = state.poptions;
         pstate = Server(SIdle);
         hs_msg_log = [||]
         hs_cur_info = new_info;
         cur_ms = ms;
         hs_next_info = init_sessionInfo
         next_ms = empty_masterSecret
         ki_crand = [||]
         ki_srand = [||]
         hs_renegotiation_info_cVerifyData = state.hs_renegotiation_info_cVerifyData
         hs_renegotiation_info_sVerifyData = state.hs_renegotiation_info_sVerifyData}

        
let rec recv_fragment_client (state:hs_state) (must_change_ver:ProtocolVersion Option) =
    match parseFragment state with
    | None ->
      match must_change_ver with
      | None      -> (correct (HSAck), state)
      | Some (pv) -> (correct (HSChangeVersion(CtoS,pv)),state)
    | Some (state,hstype,payload,to_log) ->
      match state.pstate with
      | Client(cState) ->
        match hstype with
        | HT_hello_request ->
            match cState with
            | CIdle -> (* This is a legitimate hello request. Properly handle it *)
                (* Do not log this message *)
                match state.poptions.honourHelloReq with
                | HRPIgnore -> recv_fragment_client state must_change_ver
                | HRPResume -> let state = start_rekey state state.poptions in (correct (HSAck), state) (* Terminating case, we reset all buffers *)
                | HRPFull   -> let state = start_rehandshake state state.poptions in (correct (HSAck), state) (* Terminating case, we reset all buffers *)
            | _ -> (* RFC 7.4.1.1: ignore this message *) recv_fragment_client state must_change_ver
        | HT_server_hello ->
            match cState with
            | ServerHello ->
                match parseServerHello payload with
                | Error(x,y) -> (Error(HSError(AD_decode_error),HSSendAlert),state)
                | Correct (shello,server_random) ->
                  // Sanity checks on the received message; they are security relevant. 
                  // Check that the server agreed version is between maxVer and minVer. 
                  if not (shello.server_version >= state.poptions.minVer 
                       && shello.server_version <= state.poptions.maxVer) 
                  then Error(HSError(AD_protocol_version),HSSendAlert),state
                  else
                  // Check that the negotiated ciphersuite is in the proposed list.
                  // Note: if resuming a session, we still have to check that this ciphersuite is the expected one!
                  if not (List.exists (fun x -> x = shello.cipher_suite) state.poptions.ciphersuites) 
                  then Error(HSError(AD_illegal_parameter),HSSendAlert),state
                  else
                  // Check that the compression method is in the proposed list.
                  if not (List.exists (fun x -> x = shello.compression_method) state.poptions.compressions) 
                  then Error(HSError(AD_illegal_parameter),HSSendAlert),state
                  else
                  // Handling of safe renegotiation
                  let safe_reneg_result =
                    if state.poptions.safe_renegotiation then
                        let expected = state.hs_renegotiation_info_cVerifyData @| state.hs_renegotiation_info_sVerifyData in
                        inspect_ServerHello_extensions shello.neg_extensions expected
                    else
                        // RFC Sec 7.4.1.4: with no safe renegotiation, we never send extensions; if the server sent any extension
                        // we MUST abort the handshake with unsupported_extension fatal alter (handled by the dispatcher)
                        if not (equalBytes shello.neg_extensions [||])
                        then Error(HSError(AD_unsupported_extension),HSSendAlert)
                        else let unitVal = () in correct (unitVal)
                  match safe_reneg_result with
                    | Error (x,y) -> (Error (x,y), state)
                    | Correct _ ->
                        // Log the received packet and store the server random.
                        let new_log = state.hs_msg_log @| to_log in
                        let state = {state with hs_msg_log = new_log; ki_srand = server_random}
                        (* Check whether we asked for resumption *)
                        if isNullCipherSuite state.hs_next_info.cipher_suite then
                            (* we did not request resumption, do a full handshake *)
                            (* define the sinfo we're going to establish *)
                            let next_sinfo = { clientID = None
                                               serverID = None
                                               sessionID = (if equalBytes shello.sh_session_id [||] then None else Some(shello.sh_session_id))
                                               protocol_version = shello.server_version
                                               cipher_suite = shello.cipher_suite
                                               compression = shello.compression_method
                                               init_crand = state.hs_next_info.init_crand (* or, alternatively, state.ki_crand *)
                                               init_srand = server_random
                                             } in
                            let state = {state with hs_next_info = next_sinfo} in
                            (* If DH_ANON, go into the ServerKeyExchange state, else go to the Certificate state *)
                            if isAnonCipherSuite shello.cipher_suite then
                                let state = {state with pstate = Client(ServerKeyExchange)} in
                                recv_fragment_client state (Some(shello.server_version))
                            else
                                let state = {state with pstate = Client(Certificate)} in
                                recv_fragment_client state (Some(shello.server_version))
                        else
                            match state.hs_next_info.sessionID with
                            | None -> unexpectedError "[recv_fragment] A resumed session should never have empty SID"
                            | Some(sid) ->
                                if sid = shello.sh_session_id then (* use resumption *)
                                    (* Check that protocol version, ciph_suite and compression method are indeed the correct ones *)
                                    if state.hs_next_info.protocol_version = shello.server_version then
                                        if state.hs_next_info.cipher_suite = shello.cipher_suite then
                                            if state.hs_next_info.compression = shello.compression_method then
                                                let state = compute_session_secrets_and_CCSs state CtoS in
                                                let clSpecState = { resumed_session = true;
                                                                    must_send_cert = None;
                                                                    client_certificate = None} in
                                                let state = { state with pstate = Client(CCCS(clSpecState))}
                                                recv_fragment_client state (Some(shello.server_version))
                                            else (Error(HSError(AD_illegal_parameter),HSSendAlert),state)
                                        else (Error(HSError(AD_illegal_parameter),HSSendAlert),state)
                                    else (Error(HSError(AD_illegal_parameter),HSSendAlert),state)
                                else (* server did not agreed on resumption, do a full handshake *)
                                    (* define the sinfo we're going to establish *)
                                    let next_sinfo = { clientID = None
                                                       serverID = None
                                                       sessionID = (if equalBytes shello.sh_session_id [||] then None else Some(shello.sh_session_id))
                                                       protocol_version = shello.server_version
                                                       cipher_suite = shello.cipher_suite
                                                       compression = shello.compression_method
                                                       init_crand = state.hs_next_info.init_crand (* or, alternatively, state.ki_crand *)
                                                       init_srand = server_random
                                                     } in
                                    let state = {state with hs_next_info = next_sinfo} in
                                    (* If DH_ANON, go into the ServerKeyExchange state, else go to the Certificate state *)
                                    if isAnonCipherSuite shello.cipher_suite then
                                        let state = {state with pstate = Client(ServerKeyExchange)} in
                                        recv_fragment_client state (Some(shello.server_version))
                                    else
                                        let state = {state with pstate = Client(Certificate)} in
                                        recv_fragment_client state (Some(shello.server_version))
            | _ -> (* ServerHello arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
        | HT_certificate ->
            match cState with
            | Certificate ->
                match parseCertificate payload with
                | Error(x,y) -> (Error(x,y),state)
                | Correct(certs) ->
                    if not (state.poptions.certificateValidationPolicy certs.certificate_list) then
                        (Error(HSError(AD_bad_certificate),HSSendAlert),state)
                    else (* We have validated server identity *)
                        (* Log the received packet *)
                        let new_log = state.hs_msg_log @| to_log in
                        let state = {state with hs_msg_log = new_log} in           
                        (* update the sinfo we're establishing *)
                        let next_sinfo = {state.hs_next_info with serverID = Some(certs.certificate_list.Head)} in
                        let state = {state with hs_next_info = next_sinfo} in
                        if cipherSuiteRequiresKeyExchange state.hs_next_info.cipher_suite then
                            let state = {state with pstate = Client(ServerKeyExchange)} in
                            recv_fragment_client state must_change_ver
                        else
                            let state = {state with pstate = Client(CertReqOrSHDone)} in
                            recv_fragment_client state must_change_ver
            | _ -> (* Certificate arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
        | HT_server_key_exchange ->
            match cState with
            | ServerKeyExchange ->
                (* TODO *) (Error(HSError(AD_internal_error),HSSendAlert),state)
            | _ -> (* Server Key Exchange arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
        | HT_certificate_request ->
            match cState with
            | CertReqOrSHDone ->
                (* Log the received packet *)
                let new_log = state.hs_msg_log @| to_log in
                let state = {state with hs_msg_log = new_log} in

                (* Note: in next statement, use next_info, because the handshake runs according to the session we want to
                   establish, not the current one *)
                match parseCertificateRequest state.hs_next_info.protocol_version payload with
                | Error(x,y) -> (Error(x,y),state)
                | Correct(certReqMsg) ->
                let client_cert = find_client_cert certReqMsg in
                (* Update the sinfo we're establishing *)
                let next_info = {state.hs_next_info with clientID =
                                                            match client_cert with
                                                            | None -> None
                                                            | Some(certList) -> Some(certList.Head)} in
                let state = {state with hs_next_info = next_info} in
                let clSpecState = {resumed_session = false;
                                   must_send_cert = Some(certReqMsg);
                                   client_certificate = client_cert} in
                let state = {state with pstate = Client(CSHDone(clSpecState))} in
                recv_fragment_client state must_change_ver
            | _ -> (* Certificate Request arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
        | HT_server_hello_done ->
            match cState with
            | CertReqOrSHDone ->
                if not (equalBytes payload [||]) then
                    (Error(HSError(AD_decode_error),HSSendAlert),state)
                else
                    (* Log the received packet *)
                    let new_log = state.hs_msg_log @| to_log in
                    let state = {state with hs_msg_log = new_log} in

                    let clSpecState = {
                        resumed_session = false;
                        must_send_cert = None;
                        client_certificate = None} in
                    match prepare_client_output_full state clSpecState with
                    | Error (x,y) -> (Error (x,y), state)
                    | Correct (state) ->
                        let state = {state with pstate = Client(CCCS(clSpecState))}
                        recv_fragment_client state must_change_ver
            | CSHDone(clSpecState) ->
                if not (equalBytes payload [||]) then
                    (Error(HSError(AD_decode_error),HSSendAlert),state)
                else
                    (* Log the received packet *)
                    let new_log = state.hs_msg_log @| to_log in
                    let state = {state with hs_msg_log = new_log} in

                    match prepare_client_output_full state clSpecState with
                    | Error (x,y) -> (Error (x,y), state)
                    | Correct (state) ->
                        let state = {state with pstate = Client(CCCS(clSpecState))}
                        recv_fragment_client state must_change_ver
            | _ -> (* Server Hello Done arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
        | HT_finished ->
            match cState with
            | CFinished(clSpState) ->
                (* Check received content *)
                let ki =
                    match state.ccs_incoming with
                    | None -> unexpectedError "[recv_fragment_client] ccs_incoming should have some value when in CFinished state"
                    | Some (ccs_data) -> ccs_data.ki
                let verifyDataisOK = checkVerifyData ki state.next_ms state.hs_msg_log payload in
                if not verifyDataisOK then
                    (Error(HSError(AD_decrypt_error),HSSendAlert),state)
                else
                    (* Store server verifyData, in case we use safe resumption *)
                    let state = {state with hs_renegotiation_info_sVerifyData = payload} in
                    if clSpState.resumed_session then
                        (* Log the received message *)
                        let new_log = state.hs_msg_log @| to_log in
                        let state = {state with hs_msg_log = new_log} in
                        let state = prepare_client_output_resumption state in
                        let state = {state with pstate = Client(CWaitingToWrite)} in
                        (correct (HSReadSideFinished),state)
                    else    
                        (* Handshake fully completed successfully. Report this fact to the dispatcher:
                            it will take care of moving the handshake to the Idle state, updating the sinfo with the
                            one we've been creating in this handshake. *)
                        (* Note: no need to log this message *)
                        let storableSession = { sinfo = state.hs_next_info;
                                                ms = state.next_ms;
                                                dir = CtoS}
                        (correct (HSFullyFinished_Read (storableSession)),state)
            | _ -> (* Finished arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
        | _ -> (* Unsupported/Wrong message *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
      
      (* Should never happen *)
      | Server(_) -> unexpectedError "[recv_fragment_client] should only be invoked when in client role."

// Move to Principal? 
let getServerCert cs ops =
    (* TODO: Properly get the server certificate. Note this should be a list of certificates...*)
    let data = System.IO.File.ReadAllBytes (ops.server_cert_file + ".cer") in
    match certificate_of_bytes data with
    | Error(x,y) -> Error(HSError(AD_internal_error),HSSendAlert)
    | Correct(cert) ->
        let pri = System.IO.File.ReadAllText(ops.server_cert_file + ".pvk") in
        let cert = set_priKey cert pri in
        (* FIXME TODO DEBUG: Remove next printing lines *)
        printfn "Sending certificate of"
        printfn "%s" (get_CN cert)
        correct (cert)

let prepare_server_output_full state maxClVer =
    let ext_data = state.hs_renegotiation_info_cVerifyData @| state.hs_renegotiation_info_sVerifyData in
    let (sHelloB,sRandom) = makeServerHelloBytes state.poptions state.hs_next_info ext_data in
    let next_info = {state.hs_next_info with init_srand = sRandom} in
    let state = {state with hs_next_info = next_info; ki_srand = sRandom} in
    let res =
        if isAnonCipherSuite state.hs_next_info.cipher_suite then
            correct ([||],state)
        else
            match getServerCert state.hs_next_info.cipher_suite state.poptions with
            | Error(x,y) -> Error(x,y)
            | Correct(sCert) ->
                (* update server identity in the sinfo *)
                let next_info = {state.hs_next_info with serverID = Some(sCert)} in
                let state = {state with hs_next_info = next_info} in
                correct (makeCertificateBytes (Some([sCert])), state)
    match res with
    | Error(x,y) -> Error(x,y)
    | Correct (res) ->
        let (certificateB,state) = res in
        let res =
            if isAnonCipherSuite state.hs_next_info.cipher_suite || cipherSuiteRequiresKeyExchange state.hs_next_info.cipher_suite then
                (* TODO: DH key exchange *)
                Error(HSError(AD_internal_error),HSSendAlert)
            else
                correct ([||])
        match res with
        | Error(x,y) -> Error(x,y)
        | Correct (serverKeyExchangeB) ->
            let certificateRequestB =
                if state.poptions.request_client_certificate then
                    makeCertificateRequestBytes state.hs_next_info.cipher_suite state.hs_next_info.protocol_version
                else
                    [||]
            let sHelloDoneB = makeServerHelloDoneBytes () in
            let output = sHelloB @| certificateB @| serverKeyExchangeB @| certificateRequestB @| sHelloDoneB in
            (* Log the output and put it into the output buffer *)
            let new_log = state.hs_msg_log @| output in
            let new_out = state.hs_outgoing @| output in
            let state = {state with hs_msg_log = new_log; hs_outgoing = new_out} in
            (* Compute the next state of the server *)
            let sSpecSt = { resumed_session = false
                            highest_client_ver = maxClVer} in
            let state =
                if state.poptions.request_client_certificate then
                    {state with pstate = Server(ClCert(sSpecSt))}
                else
                    {state with pstate = Server(ClientKEX(sSpecSt))}
            correct (state)


// The server "negotiates" its first proposal included in the client's proposal
let negotiate cList sList =
    List.tryFind (fun s -> List.exists (fun c -> c = s) cList) sList

let prepare_server_output_resumption state =
    let ext_data = state.hs_renegotiation_info_cVerifyData @| state.hs_renegotiation_info_sVerifyData in
    let (sHelloB,sRandom) = makeServerHelloBytes state.poptions state.hs_next_info ext_data in
    let state = {state with ki_srand = sRandom} in
    let new_out = state.hs_outgoing @| sHelloB in
    let new_log = state.hs_msg_log  @| sHelloB in
    let state = {state with hs_outgoing = new_out; hs_msg_log = new_log} in
    let state = compute_session_secrets_and_CCSs state StoC in
    let ki =
        match state.ccs_outgoing with
        | None -> unexpectedError "[prepare_server_output_resumption] The ccs_outgoing buffer should contain some value when computing the finished message"
        | Some (_,ccs_data) -> ccs_data.ki
    let (finishedB,verifyData) = makeFinishedMsgBytes ki state.next_ms state.hs_msg_log in
    (* match makeFinishedMsgBytes sinfo.protocol_version sinfo.cipher_suite sinfo.more_info.mi_ms StoC state.hs_msg_log with *)
    let new_out = state.hs_outgoing_after_ccs @| finishedB in
    let new_log = state.hs_msg_log @| finishedB in
    let sSpecState = {resumed_session = true
                      highest_client_ver = state.hs_next_info.protocol_version} (* Highest version is useless with resumption. We already agree on the MS *)
    let state = {state with hs_outgoing_after_ccs = new_out
                            hs_msg_log = new_log
                            hs_renegotiation_info_sVerifyData = verifyData
                            pstate = Server(SCCS(sSpecState))} in
    state

let rec recv_fragment_server (state:hs_state) (must_change_ver:ProtocolVersion Option) =
    match parseFragment state with
    | None ->
      match must_change_ver with
      | None      -> (correct (HSAck), state)
      | Some (pv) -> (correct (HSChangeVersion(StoC,pv)),state)
    | Some (state,hstype,payload,to_log) ->
      match state.pstate with
      | Server(sState) ->
        match hstype with
        | HT_client_hello ->
            match sState with
            | x when x = ClientHello || x = SIdle ->
                match parseClientHello payload with
                | Error(x,y) -> (Error(HSError(AD_decode_error),HSSendAlert),state)
                | Correct (cHello,cRandom) ->
                let state = {state with ki_crand = cRandom} in
                (* Log the received message *)
                let new_log = state.hs_msg_log @| to_log in
                let state = {state with hs_msg_log = new_log} in
                (* Handling of renegotiation_info extenstion *)
                let extRes =
                    if state.poptions.safe_renegotiation then
                        if check_client_renegotiation_info cHello state.hs_renegotiation_info_cVerifyData then
                            correct(state)
                        else
                            (* We don't accept an insecure client *)
                            Error(HSError(AD_handshake_failure),HSSendAlert)
                    else
                        (* We can ignore the extension, if any *)
                        correct(state)
                match extRes with
                | Error(x,y) -> (Error(x,y),state)
                | Correct(state) ->
                    (* Check whether the client asked for session resumption *)
                    if equalBytes cHello.ch_session_id [||] 
                    then 
                        (* Client asked for a full handshake *)
                        startServerFull state cHello
                    else
                        (* Client asked for resumption, let's see if we can satisfy the request *)
                        (* FIXME: this SessionDB interaction seems right to be here, however, I'd like to move
                           all SessionDB in the Dispatch. (Why in the Dispatcher? Not sure) *)
                        match select state.poptions cHello.ch_session_id with
                        | None ->
                            (* We don't have the requested session stored, go for a full handshake *)
                            startServerFull state cHello
                        | Some (storedSession) ->
                            (* Check that the client proposed algorithms match those of our stored session *)
                            match storedSession.dir with
                            | CtoS -> (* This session is not for us, we're a server. Do full handshake *)
                                startServerFull state cHello
                            | StoC ->
                                if cHello.client_version >= storedSession.sinfo.protocol_version then
                                    (* We have a common version *)
                                    if not (List.exists (fun cs -> cs = storedSession.sinfo.cipher_suite) cHello.cipher_suites) then
                                        (* Do a full handshake *)
                                        startServerFull state cHello
                                    else if not (List.exists (fun cm -> cm = storedSession.sinfo.compression) cHello.compression_methods) then
                                        (* Do a full handshake *)
                                        startServerFull state cHello
                                    else
                                        (* Everything is ok, proceed with resumption *)
                                        let state = {state with hs_next_info = storedSession.sinfo
                                                                next_ms = storedSession.ms}
                                        let state = prepare_server_output_resumption state 
                                        recv_fragment_server state (Some(storedSession.sinfo.protocol_version))
                                else
                                    (* Do a full handshake *)
                                    startServerFull state cHello
                                    
            | _ -> (* Message arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
        | HT_certificate ->
            match sState with
            | ClCert (sSpecSt) ->
                match parseCertificate payload with
                | Error(x,y) -> (Error(x,y),state)
                | Correct(certMsg) ->
                    if not (state.poptions.certificateValidationPolicy certMsg.certificate_list) then
                        (Error(HSError(AD_bad_certificate),HSSendAlert),state)
                    else (* We have validated client identity *)
                        (* Log the received packet *)
                        let new_log = state.hs_msg_log @| to_log in
                        let state = {state with hs_msg_log = new_log} in           
                        (* update the sinfo we're establishing *)
                        let next_info =
                            if certMsg.certificate_list.IsEmpty then
                                {state.hs_next_info with clientID = None}
                            else
                                {state.hs_next_info with clientID = Some(certMsg.certificate_list.Head)}
                        let state = {state with hs_next_info = next_info} in
                        (* move to the next state *)
                        let state = {state with pstate = Server(ClientKEX(sSpecSt))} in
                        recv_fragment_server state must_change_ver
            | _ -> (* Message arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
        | HT_client_key_exchange ->
            match sState with
            | ClientKEX(sSpecSt) ->
                match parseClientKEX state.hs_next_info sSpecSt state.poptions payload with
                | Error(x,y) -> (Error(x,y),state)
                | Correct(pms) ->
                    (* Log the received packet *)
                    let new_log = state.hs_msg_log @| to_log in
                    let state = {state with hs_msg_log = new_log} in
                    let ms = prfMS state.hs_next_info pms in
                    (* assert: state.hs_next_info.{c,s}rand = state.ki_{c,s}rand *)
                    (* match compute_master_secret pms sinfo.more_info.mi_protocol_version state.hs_client_random state.hs_server_random with *)
                    (* TODO: here we should shred pms *)
                    let state = {state with next_ms = ms} in
                    let state = compute_session_secrets_and_CCSs state StoC in
                        (* move to new state *)
                    match state.hs_next_info.clientID with
                    | None -> (* No client certificate, so there will be no CertificateVerify message *)
                        let state = {state with pstate = Server(SCCS(sSpecSt))} in
                        recv_fragment_server state must_change_ver
                    | Some(cert) ->
                        if certificate_has_signing_capability cert then
                            let state = {state with pstate = Server(CertificateVerify(sSpecSt))} in
                            recv_fragment_server state must_change_ver
                        else
                            let state = {state with pstate = Server(SCCS(sSpecSt))} in
                            recv_fragment_server state must_change_ver
            | _ -> (* Message arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
        | HT_certificate_verify ->
            match sState with
            | CertificateVerify(sSpecSt) ->
                match state.hs_next_info.clientID with
                | None -> (* There should always be a client certificate in this state *)(Error(HSError(AD_internal_error),HSSendAlert),state)
                | Some(clCert) ->
                    match certificateVerifyCheck state payload with
                    | Error(x,y) -> (Error(x,y),state)
                    | Correct(verifyOK) ->
                        if verifyOK then
                            (* Log the message *)
                            let new_log = state.hs_msg_log @| to_log in
                            let state = {state with hs_msg_log = new_log} in   
                            (* move to next state *)
                            let state = {state with pstate = Server(SCCS(sSpecSt))} in
                            recv_fragment_server state must_change_ver
                        else
                            (Error(HSError(AD_decrypt_error),HSSendAlert),state)
            | _ -> (* Message arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
        | HT_finished ->
            match sState with
            | SFinished(sSpecSt) ->
                let kiIn =
                    match state.ccs_incoming with
                    | None -> unexpectedError "[recv_fragment_server] the incoming KeyInfo should be set now"
                    | Some (ccs_data) -> ccs_data.ki
                let verifyDataisOK = checkVerifyData kiIn state.next_ms state.hs_msg_log payload in
                (* match checkVerifyData sinfo.protocol_version sinfo.cipher_suite sinfo.more_info.mi_ms CtoS state.hs_msg_log payload with *)
                if not verifyDataisOK then
                    (Error(HSError(AD_decrypt_error),HSSendAlert),state)
                else
                    (* Save client verify data to possibly use it in the renegotiation_info extension *)
                    let state = {state with hs_renegotiation_info_cVerifyData = payload} in
                    if sSpecSt.resumed_session then
                        (* Handshake fully completed successfully. Report this fact to the dispatcher:
                            it will take care of moving the handshake to the Idle state, updating the sinfo with the
                            one we've been creating in this handshake. *)
                        (* Note: no need to log this message *)
                        let storableSession = { sinfo = state.hs_next_info
                                                ms = state.next_ms
                                                dir = StoC}
                        (correct (HSFullyFinished_Read (storableSession)),state)
                    else
                        (* Log the received message *)
                        let new_log = state.hs_msg_log @| to_log in
                        let state = {state with hs_msg_log = new_log} in
                        let kiOut =
                            match state.ccs_outgoing with
                            (* FIXME: There is at least one race condition where the following unexpected error will occur.
                                After the client sends its ClientKeyExchange message we compute the ougoing (and incoming) ccs_data,
                                and put it into our output buffer. Now, if the client hangs after the ClientKeyExchange (that is: it does
                                not send its CCS soon enough), the Dispatch module will stop reading and we will flush our output buffers,
                                thus clearing the outgoing KeyInfo. A subsequent read/write operation will trigger this code, which will
                                miserably fail.
                                Still, in the current implementation we must remove the ccs_data from the output buffer, in order to
                                send it only once. A better implementation keeps explicit track of the output message to be sent, and
                                do not rely on the content of the buffers, so we can store the outgoing ccs_data indefintely
                                (i.e. until we reset our state) exactly like we do for the incoming ccs_data *)
                            | None -> unexpectedError "[recv_fragment_server] Outgoing KeyInfo should be set now"
                            | Some(_,ccs_data) -> ccs_data.ki
                        let (packet,verifyData) = makeFinishedMsgBytes kiOut state.next_ms state.hs_msg_log in
                        (* match makeFinishedMsgBytes sinfo.protocol_version sinfo.cipher_suite sinfo.more_info.mi_ms StoC state.hs_msg_log with *)
                        let new_out = state.hs_outgoing_after_ccs @| packet in
                        let state = {state with hs_outgoing_after_ccs = new_out
                                                hs_renegotiation_info_sVerifyData = verifyData
                                                pstate = Server(SWaitingToWrite)} in
                        (correct (HSReadSideFinished),state)                                
            | _ -> (* Message arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
        | _ -> (* Unsupported/Wrong message *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
      (* Should never happen *)
      | Client(_) -> unexpectedError "[recv_fragment_server] should only be invoked when in server role."

and startServerFull state cHello =  
    // Negotiate the protocol parameters
    match minPV cHello.client_version state.poptions.maxVer with
    | version when version >= ProtocolVersion.SSL_3p0 ->
        match negotiate cHello.cipher_suites state.poptions.ciphersuites with
        | Some(cs) ->
            match negotiate cHello.compression_methods state.poptions.compressions with
            | Some(cm) ->
                (* TODO: now we don't support safe_renegotiation, and we ignore any client proposed extension *)
                let sid = mkRandom 32 in
                (* Fill in the session info we're establishing *)
                let next_info = { clientID         = None
                                  serverID         = None
                                  sessionID        = Some(sid)
                                  protocol_version = version
                                  cipher_suite     = cs
                                  compression      = cm
                                  init_crand       = state.ki_crand
                                  init_srand       = [||] }
                let state = {state with hs_next_info = next_info} in
                match prepare_server_output_full state cHello.client_version with
                | Correct(state) -> recv_fragment_server state (Some(version)) 
                | Error(x,y)     -> (Error(x,y),state)
            | None -> (Error(HSError(AD_handshake_failure),HSSendAlert),state)
        | None ->     (Error(HSError(AD_handshake_failure),HSSendAlert),state)
    | _ ->            (Error(HSError(AD_handshake_failure),HSSendAlert),state) 


let enqueue_fragment state fragment =
    let new_inc = state.hs_incoming @| fragment in
    {state with hs_incoming = new_inc}

let recv_fragment (state:hs_state) (tlen:int) (fragment:fragment) =
    (* Note, we receive fragments in the current session, not the one we're establishing *)
    (* FIXME: This session might be wrong, in the CCS/Finished/FullyFinished(Idle) transition. But we don't care now *)
    let fragment = pub_fragment_to_bytes state.hs_cur_info tlen fragment in
    let state = enqueue_fragment state fragment in
    match state.pstate with
    | Client (_) -> recv_fragment_client state None
    | Server (_) -> recv_fragment_server state None

let recv_ccs (state: hs_state) (tlen:int) (fragment:fragment): ((ccs_data Result) * hs_state) =
    (* Some parsing *)
    let fragment = pub_fragment_to_bytes state.hs_cur_info tlen fragment in
    if length fragment <> 1 then
        (Error(HSError(AD_decode_error),HSSendAlert),state)
    else
        if (int_of_bytes fragment) <> 1 then
            (Error(HSError(AD_decode_error),HSSendAlert),state)
        else
            (* CCS is good *)
            match state.pstate with
            | Client (cstate) ->
                (* Check we are in the right state (CCCS) *)
                match cstate with
                | CCCS (clSpState) ->
                    match state.ccs_incoming with
                    | None -> unexpectedError "[recv_ccs] when in CCCS state, ccs_incoming should have some value."
                    | Some (ccs_result) ->
                        let state = {state with (* ccs_incoming = None *) (* Don't reset its value now. We'll need it when computing the other side Finished message *)
                                                      pstate = Client (CFinished (clSpState))} in
                        (correct(ccs_result),state)
                | _ -> (* CCS arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
            | Server (sState) ->
                match sState with
                | SCCS (sSpecSt) ->
                    match state.ccs_incoming with
                    | None -> unexpectedError "[recv_ccs] when in CCCS state, ccs_incoming should have some value."
                    | Some (ccs_result) ->
                        let state = {state with (* ccs_incoming = None *) (* Don't reset its value now. We'll need it when computing the other side Finished message *)
                                                      pstate = Server(SFinished(sSpecSt))} in
                        (correct(ccs_result),state)
                | _ -> (* CCS arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),state)
