(* Handshake protocol *) 
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
(* open OtherCrypto *)

type clientSpecificState =
    { resumed_session: bool
      must_send_cert: certificateRequest Option
      client_certificate: (cert list) Option
    }

type serverSpecificState =
    { resumed_session: bool
      highest_client_ver: ProtocolVersionType}

type clientState =
    | ServerHello
    | Certificate
    | ServerKeyExchange
    | CertReqOrSHDone
    | CSHDone of clientSpecificState
    | CCCS of clientSpecificState
    | CFinished of clientSpecificState
    | CWatingToWrite
    | CIdle

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
  hs_outgoing    : bytes (* outgiong data before a ccs *)
  ccs_outgoing: (bytes * ccs_data) option (* marker telling there's a ccs ready *)
  hs_outgoing_after_ccs: bytes (* data to be sent after the ccs has been sent *)
  hs_incoming    : bytes (* partial incoming HS message *)
  ccs_incoming: ccs_data option (* used to store the computed secrects for receving data. Not set when receiving CCS, but when we compute the session secrects *)
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
    (* Assumptions: The buffer are filled in the following order:
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
                        | CWatingToWrite ->
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
  | HSChangeVersion of Direction * ProtocolVersionType 
                          (* ..., and we should use this new protocol version for sending *) 
  | HSReadSideFinished
  | HSFullyFinished_Read of StorableSession (* ..., and we can start sending data on the connection *)

let negotiate cList sList =
    List.tryFind (
        fun cAlg -> (
                    List.exists (fun sAlg -> sAlg = cAlg) sList
        )
    ) cList

let makeHSPacket ht data =
    let htb = bytes_of_hs_type ht in
    let len = length data in
    let blen = bytes_of_int 3 len in
    htb @| blen @| data

let makeExtStructBytes extType data =
    let extBytes = bytes_of_HExt extType in
    let payload = vlenBytes_of_bytes 2 data in
    extBytes @| payload

let makeExtBytes data =
    vlenBytes_of_bytes 2 data

let makeHelloRequestBytes () =
    makeHSPacket HT_hello_request [||]

let makeTimestamp () = (* FIXME: we may need to abstract this function *)
    let t = (System.DateTime.UtcNow - new System.DateTime(1970, 1, 1))
    (int) t.TotalSeconds

let makeRenegExtBytes verifyData =
    let payload = vlenBytes_of_bytes 1 verifyData in
    makeExtStructBytes HExt_renegotiation_info payload

let makeCHello poptions session prevCVerifyData =
    let random = { time = makeTimestamp ();
                   rnd = OtherCrypto.mkRandom 28} in
    let ext =
        if poptions.safe_renegotiation then
            makeExtBytes (makeRenegExtBytes prevCVerifyData)
        else
            [||]
    {
    client_version = poptions.maxVer
    ch_random = random
    ch_session_id = session
    cipher_suites = poptions.ciphersuites
    compression_methods = poptions.compressions
    extensions = ext
    }

(* Obsolete. Use PRFs.prfMS instead *)
(*
let compute_master_secret pms ver crandom srandom = 
    match ver with 
    | ProtocolVersionType.SSL_3p0 ->
        match ssl_prf pms (append crandom srandom) 48 with
        | Error(x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
        | Correct (res) -> correct (res)
    | x when x = ProtocolVersionType.TLS_1p0 || x = ProtocolVersionType.TLS_1p1 ->
        match prf pms "master secret" (append crandom srandom) 48 with
        | Error(x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
        | Correct (res) -> correct (res)
    | ProtocolVersionType.TLS_1p2 ->
        match tls12prf pms "master secret" (append crandom srandom) 48 with
        | Error(x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
        | Correct (res) -> correct (res)
    | _ -> Error(HSError(AD_internal_error),HSSendAlert)
*)

let rec b_of_cslist cslist acc =
    match cslist with
    | [] -> vlenBytes_of_bytes 2 acc
    | h::t ->
        let csb = bytes_of_cipherSuite h in
        let acc = acc @| csb in
        b_of_cslist t acc

let bytes_of_cipherSuites cslist =
    b_of_cslist cslist [||]

let rec b_of_complist complist acc =
    match complist with
    | [] -> vlenBytes_of_bytes 1 acc
    | h::t ->
        let compb = byte_of_compression h in
        let acc = acc @| [|compb|] in
        b_of_complist t acc

let bytes_of_compressionMethods complist =
    b_of_complist complist [||]

let makeCHelloBytes poptions session cVerifyData =
    let cHello = makeCHello poptions session cVerifyData in
    let cVerB = bytes_of_protocolVersionType cHello.client_version in
    let tsbytes = bytes_of_int 4 cHello.ch_random.time in
    let random = tsbytes @| cHello.ch_random.rnd in
    let csessB = vlenBytes_of_bytes 1 cHello.ch_session_id in
    let ccsuitesB = bytes_of_cipherSuites cHello.cipher_suites in
    let ccompmethB = bytes_of_compressionMethods cHello.compression_methods in
    let data = cVerB @| random @| csessB @| ccsuitesB @| ccompmethB @| cHello.extensions in
    ((makeHSPacket HT_client_hello data),random)

let makeSHelloBytes poptions sinfo prevVerifData =
    let verB = bytes_of_protocolVersionType sinfo.protocol_version in
    let tsB = bytes_of_int 4 (makeTimestamp ()) in
    let randB = OtherCrypto.mkRandom 28 in
    let sRandom = tsB @| randB in
    let sidRaw =
        match sinfo.sessionID with
        | None -> [||]
        | Some(sid) -> sid
    let sidB = vlenBytes_of_bytes 1 sidRaw in
    let csB = bytes_of_cipherSuite sinfo.cipher_suite in
    let cmB = [|byte_of_compression sinfo.compression|] in
    let ext =
        if poptions.safe_renegotiation then
            let ren_extB = makeRenegExtBytes prevVerifData in
            makeExtBytes ren_extB
        else
            [||]
    let data = verB @| sRandom @| sidB @| csB @| cmB @| ext in
    ((makeHSPacket HT_server_hello data),sRandom)

let bytes_of_certificates certList =
    List.map bytes_of_certificate certList

let rec certList_to_bytes certList acc =
    match certList with
    | h::t ->
        let acc = acc @| h in
        certList_to_bytes t acc
    | [] -> acc

let makeCertificateBytes certOpt =
    match certOpt with
    | None ->
        let data = vlenBytes_of_bytes 3 [||] in
        makeHSPacket HT_certificate data
    | Some(certList) ->
        let pre_data = bytes_of_certificates certList in
        let pre_data = List.map (fun cer -> vlenBytes_of_bytes 3 cer) pre_data in
        let pre_data = certList_to_bytes pre_data [||] in
        let data = vlenBytes_of_bytes 3 pre_data in
        makeHSPacket HT_certificate data

let makeCertificateRequestBytes cs ver =
    (* TODO: now we send all possible choiches, including inconsistent ones, and we hope the client will pick the proper one. *)
    let rsaB = bytes_of_int 1 (int ClientCertType.CLT_RSA_Sign) in
    let dsaB = bytes_of_int 1 (int ClientCertType.CLT_DSS_Sign) in
    let rsafixedB = bytes_of_int 1 (int ClientCertType.CLT_RSA_Fixed_DH) in
    let dsafixedB = bytes_of_int 1 (int ClientCertType.CLT_DSS_Fixed_DH) in
    let certTypes = rsaB @| dsaB @| rsafixedB @| dsafixedB in
    let certTypes = vlenBytes_of_bytes 1 certTypes in
    let sigAndAlg =
        match ver with
        | ProtocolVersionType.TLS_1p2 ->
            (* For no particular reason, we will offer rsa-sha1 and dsa-sha1 *)
            let rsaSigB = bytes_of_int 1 (int SigAlg.SA_rsa) in
            let dsaSigB = bytes_of_int 1 (int SigAlg.SA_dsa) in
            let sha1B = bytes_of_int 1 (hashAlg_to_tls12enum Algorithms.hashAlg.SHA) in
            let sigAndAlg = sha1B @| rsaSigB @| sha1B @| dsaSigB in
            vlenBytes_of_bytes 2 sigAndAlg
        | v when v >= ProtocolVersionType.SSL_3p0 ->
            [||]
        | _ -> unexpectedError "[makeCertificateRequestBytes] invoked on unknown protocol version."
    (* We specify no cert auth *)
    let distNames = vlenBytes_of_bytes 2 [||] in
    let data = certTypes @| sigAndAlg @| distNames in
    makeHSPacket HT_certificate_request data


let makeSHelloDoneBytes unitVal =
    makeHSPacket HT_server_hello_done [||]

let makeClientKEXBytes hs_state clSpecInfo =
    if canEncryptPMS hs_state.hs_next_info.cipher_suite then
        let pms = genPMS hs_state.hs_next_info hs_state.poptions.maxVer in
        match hs_state.hs_next_info.serverID with
        | None -> unexpectedError "[makeClientKEXBytes] Server certificate should always be present with a RSA signing cipher suite."
        | Some (serverCert) ->
            let pubKey = pubKey_of_certificate serverCert in
            match rsaEncryptPMS pubKey pms with
            | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
            | Correct (encpms) ->
                if hs_state.hs_next_info.protocol_version = ProtocolVersionType.SSL_3p0 then
                    correct ((makeHSPacket HT_client_key_exchange encpms),pms)
                else
                    let encpms = vlenBytes_of_bytes 2 encpms in
                    correct ((makeHSPacket HT_client_key_exchange encpms),pms)
    else
        match clSpecInfo.must_send_cert with
        | Some (_) ->
            match hs_state.hs_next_info.clientID with
            | None -> (* Client certificate not sent, (and not in RSA mode)
                         so we must use DH parameters *)
                (* TODO: send public Yc value *)
                let ycBytes = [||] in
                (* TODO: compute pms *)
                let pms = empty_pms in
                correct ((makeHSPacket HT_client_key_exchange ycBytes),pms)
            | Some (cert) ->
                (* TODO: check whether the certificate already contained suitable DH parameters *)
                let pms = empty_pms in
                correct ((makeHSPacket HT_client_key_exchange [||]),pms)
        | None ->
            (* Use DH parameters *)
            let ycBytes = [||] in
            let pms = empty_pms in
            correct ((makeHSPacket HT_client_key_exchange ycBytes),pms)

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
    | ProtocolVersionType.TLS_1p2 ->
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
            match HASH.hash hashAlg data with
            | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
            | Correct (hashed) ->
                match OtherCrypto.rsaEncrypt priKey hashed with
                | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
                | Correct (signed) ->
                    let signed = vlenBytes_of_bytes 2 signed in
                    let hashAlgBytes = bytes_of_int 1 (hashAlg_to_tls12enum hashAlg) in
                    let signAlgBytes = bytes_of_int 1 (int SigAlg.SA_rsa) in
                    let payload = hashAlgBytes @| signAlgBytes @| signed in
                    correct (makeHSPacket HT_certificate_verify payload)
    | x when x = ProtocolVersionType.TLS_1p0 || x = ProtocolVersionType.TLS_1p1 ->
        (* TODO *) Error(HSError(AD_internal_error),HSSendAlert)
    | ProtocolVersionType.SSL_3p0 ->
        (* TODO *) Error(HSError(AD_internal_error),HSSendAlert)
    | _ -> Error(HSError(AD_internal_error),HSSendAlert)

let makeCCSBytes () =
    bytes_of_int 1 1

(* Obsolete. Use PRFs.prfKeyExp instead *)
(*
let expand_master_secret ver ms crandom srandom nb = 
  match ver with 
  | ProtocolVersionType.SSL_3p0 -> 
     match ssl_prf ms (append srandom crandom) nb with
     | Error(x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
     | Correct (res) -> correct (res)
  | x when x = ProtocolVersionType.TLS_1p0 || x = ProtocolVersionType.TLS_1p1 ->
     match prf ms "key expansion" (append srandom crandom) nb with
     | Error (x,y) -> Error(HSError(AD_decrypt_error),HSSendAlert)
     | Correct (res) -> correct(res)
  | ProtocolVersionType.TLS_1p2 ->
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
    match prfKeyExp outKi ms with
    | Error (x,y) -> Error (x,y)
    | Correct (key_block) ->
        let (cmk,smk,cek,sek,civ,siv) = splitKeys outKi inKi key_block in
        match outKi.dir with 
            | CtoS -> correct (smk,sek,siv,cmk,cek,civ)
            | StoC -> correct (cmk,cek,civ,smk,sek,siv)

(* Obsolete. Use PRFs.prfVerifyData instead *)
(*
let bldVerifyData ver cs ms entity hsmsgs = 
  (* FIXME: There should be only one (verifyData)prf function in CryptoTLS, that takes
     ver and cs and performs the proper computation *)
  match ver with 
  | ProtocolVersionType.SSL_3p0 ->
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
  | x when x = ProtocolVersionType.TLS_1p0 || x = ProtocolVersionType.TLS_1p1 -> 
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
  | ProtocolVersionType.TLS_1p2 ->
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
    match prfVerifyData ki ms hsmsgs with
    | Error (x,y) -> Error (x,y)
    | Correct (computed) -> correct (orig = computed)

let makeFinishedMsgBytes ki ms hsmsgs =
    match prfVerifyData ki ms hsmsgs with
    | Error (x,y) -> Error (x,y)
    | Correct (payload) -> correct ((makeHSPacket HT_finished payload), payload)

(*
let ciphstate_of_ciphtype ct key iv =
    match ct with
    | CT_block -> BlockCipherState (key,iv)
    | CT_stream -> StreamCipherState
*)

let split_varLen data lenSize =
    let (lenBytes,data) = split data lenSize in
    let len = int_of_bytes lenBytes in
    split data len

let rec extensionList_of_bytes_int data list =
    match length data with
    | 0 -> correct (list)
    | x when x > 0 && x < 4 ->
        (* This is a parsing error, or a malformed extension *)
        Error (HSError(AD_decode_error), HSSendAlert)
    | _ ->
        let (extTypeBytes,rem) = split data 2 in
        let extType = hExt_of_bytes extTypeBytes in
        let (payload,rem) = split_varLen rem 2 in
        extensionList_of_bytes_int rem ([(extType,payload)] @ list)

let extensionList_of_bytes data =
    match length data with
    | 0 -> correct ([])
    | 1 -> Error(HSError(AD_decode_error),HSSendAlert)
    | _ ->
        let (exts,rem) = split_varLen data 2 in
        if not (equalBytes rem [||]) then
            Error(HSError(AD_decode_error),HSSendAlert)
        else
            extensionList_of_bytes_int exts []

let parseCHello data =
    let (clVerBytes,data) = split data 2 in
    let clVer = protocolVersionType_of_bytes clVerBytes in
    let (clTsBytes,data) = split data 4 in
    let clTs = int_of_bytes clTsBytes in
    let (clRdmBytes,data) = split data 28 in
    let clRdm = {time = clTs; rnd = clRdmBytes} in
    let (sid,data) = split_varLen data 1 in
    let (clCiphsuitesBytes,data) = split_varLen data 2 in
    let clCiphsuites = cipherSuites_of_bytes clCiphsuitesBytes in
    let (cmBytes,data) = split_varLen data 1 in
    let cm = compressions_of_bytes cmBytes in
    ({ client_version = clVer
       ch_random = clRdm
       ch_session_id = sid
       cipher_suites = clCiphsuites
       compression_methods = cm
       extensions = data},
     clTsBytes @| clRdmBytes
    )

let parseSHello data =
    let (serverVerBytes,data) = split data 2 in
    let serverVer = protocolVersionType_of_bytes serverVerBytes in
    let (serverTsBytes,data) = split data 4 in
    let serverTs = int_of_bytes serverTsBytes in
    let (serverRdmBytes,data) = split data 28 in
    let serverRdm = {time = serverTs; rnd = serverRdmBytes} in
    let (sid,data) = split_varLen data 1 in
    let (csBytes,data) = split data 2 in
    let cs = cipherSuite_of_bytes csBytes in
    let (cmBytes,data) = split data 1 in
    let cm = compression_of_byte cmBytes.[0] in
    ({ server_version = serverVer
       sh_random = serverRdm
       sh_session_id = sid
       cipher_suite = cs
       compression_method = cm
       neg_extensions = data},
      serverTsBytes @| serverRdmBytes)

let check_reneg_info payload expected =
    let (recv,rem) = split_varLen payload 1 in
    if not (equalBytes recv expected) then
        false
    else
        (* Also check there were no more data in this extension! *)
        if not (equalBytes rem [||]) then
            false
        else
            true

let check_client_renegotiation_info cHello expected =
    match extensionList_of_bytes cHello.extensions with
    | Error(x,y) -> false
    | Correct(extList) ->
        (* Check there's at most one renegotiation_info extension *)
        let ren_ext_list = List.filter (fun (ext,_) -> ext = HExt_renegotiation_info) extList in
        if ren_ext_list.Length > 1 then
            false
        else
            let has_SCSV = contains_TLS_EMPTY_RENEGOTIATION_INFO_SCSV cHello.cipher_suites in
            if equalBytes expected [||] then
                (* First handshake *)
                if ren_ext_list.Length = 0 then
                    if has_SCSV then
                        (* Client gave SCSV, and no extension. This is OK for first handshake *)
                        true
                    else
                        (* Client doesn't support this extension, we fail *)
                        false
                else
                    let ren_ext = ren_ext_list.Head in
                    let (extType,payload) = ren_ext in
                    check_reneg_info payload expected
            else
                (* Not first handshake *)
                if has_SCSV || (ren_ext_list.Length = 0) then
                    false
                else
                    let ren_ext = ren_ext_list.Head in
                    let (extType,payload) = ren_ext in
                    check_reneg_info payload expected
                
                

let inspect_SHello_extensions recvExt expected =
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

let rec parseCertificate_int toProcess list =
    if equalBytes toProcess [||] then
        correct(list)
    else
        let (nextCertBytes,toProcess) = split_varLen toProcess 3 in
        match certificate_of_bytes nextCertBytes with
        | Error(x,y) -> Error(HSError(AD_bad_certificate),HSSendAlert)
        | Correct(nextCert) ->
            let list = list @ [nextCert] in
            parseCertificate_int toProcess list

let parseCertificate data =
    let (certList,_) = split_varLen data 3 in
    match parseCertificate_int certList [] with
    | Error(x,y) -> Error(x,y)
    | Correct(certList) -> correct({certificate_list = certList})

let rec certTypeList_of_bytes data res =
    if length data > 1 then
        let (thisByte,data) = split data 1 in
        let thisInt = int_of_bytes thisByte in
        let res = [enum<ClientCertType>thisInt] @ res in
        certTypeList_of_bytes data res
    else
        let thisInt = int_of_bytes data in
        [enum<ClientCertType>thisInt] @ res

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
    if length data > 0 then
        let (nameBytes,data) = split_varLen data 2 in
        let name = iutf8 nameBytes in (* FIXME: I have no idea wat "X501 represented in DER-encoding format" (RFC 5246, page 54) is. I assume UTF8 will do. *)
        let res = [name] @ res in
        distNamesList_of_bytes data res
    else
        res

let parseCertReq ver data =
    let (certTypeListBytes,data) = split_varLen data 1 in
    let certTypeList = certTypeList_of_bytes certTypeListBytes [] in
    let sigAlgsAndData = (
        if ver = ProtocolVersionType.TLS_1p2 then
            let (sigAlgsBytes,data) = split_varLen data 2 in
            match sigAlgsList_of_bytes sigAlgsBytes [] with
            | Error(x,y) -> Error(x,y)
            | Correct (sigAlgsList) ->
                correct (Some(sigAlgsList),data)
        else
            correct (None,data)) in
    match sigAlgsAndData with
    | Error(x,y) -> Error(x,y)
    | Correct ((sigAlgs,data)) ->
    let (distNamesBytes,_) = split_varLen data 2 in
    let distNamesList = distNamesList_of_bytes distNamesBytes [] in
    let res = { client_certificate_type = certTypeList;
                signature_and_hash_algorithm = sigAlgs;
                certificate_authorities = distNamesList} in
    correct (res)

let find_client_cert (certReqMsg:certificateRequest) : (cert list) option =
    (* TODO *) None

let parseClientKEX sinfo sSpecState pops data =
    if canEncryptPMS sinfo.cipher_suite then
        match sinfo.serverID with
        | None -> unexpectedError "[parseClientKEX] when the ciphersuite can encrypt the PMS, the server certificate should always be set"
        | Some(cert) ->
            (* parse the message *)
            let parseRes =
                match sinfo.protocol_version with
                | ProtocolVersionType.SSL_3p0 ->
                    correct (data)
                | v when v >= ProtocolVersionType.TLS_1p0 ->
                        let (encPMS,rem) = split_varLen data 2 in
                        if length rem = 0 then
                            correct (encPMS)
                        else
                            Error(HSError(AD_decode_error),HSSendAlert)
                | _ -> Error(HSError(AD_internal_error),HSSendAlert)
            match parseRes with
            | Error(x,y) -> Error(x,y)
            | Correct(encPMS) ->
                let res = getPMS sinfo sSpecState.highest_client_ver pops.check_client_version_in_pms_for_old_tls cert encPMS in
                correct(res)
    else
        (* TODO *)
        (* We should support the DH key exchanges *)
        Error(HSError(AD_internal_error),HSSendAlert)

let certificateVerifyCheck (hs_state:hs_state) (payload:bytes) =
    (* TODO: pretend client sent valid verification data. We need to understand how to treat certificates and related algorithms properly *)
    correct(true)

let compute_session_secrets_and_CCSs hs_state dir =
    (* Create KeyInfos *)
    let outKi = { sinfo = hs_state.hs_next_info;
                  dir = dir;
                  crand = hs_state.ki_crand;
                  srand = hs_state.ki_srand;
                }
    let inKi = { sinfo = hs_state.hs_next_info;
                 dir = dualDirection dir;
                 crand = hs_state.ki_crand;
                 srand = hs_state.ki_srand;
                }
    match generateKeys outKi inKi hs_state.next_ms with
    | Error (x,y) -> Error(x,y)
    | Correct(allKeys) ->
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
        let hs_state = {hs_state with ccs_outgoing = Some((makeCCSBytes(),write_ccs_data))
                                      ccs_incoming = Some(read_ccs_data)} in
        correct (hs_state)

let prepare_client_output_full hs_state clSpecState =
    let clientCertBytes =
        match clSpecState.must_send_cert with
        | Some (_) ->
            makeCertificateBytes clSpecState.client_certificate
        | None ->
            [||]

    match makeClientKEXBytes hs_state clSpecState with
    | Error (x,y) -> Error (x,y)
    | Correct (result) ->
        let (clientKEXBytes,pms) = result in
        match prfMS hs_state.hs_next_info pms with
        (* Assert: hs_state.hs_next_info.{c,s}rand = hs_state.ki_{c,s}rand
           In fact, we want to use the {c,s}rand just used in this session (and not the constant sinfo ones).
           And indeed, the PMS is computed only during the first session
           where the assertion must be true. *)
        (* Original code:
        match compute_master_secret pms sinfo.more_info.mi_protocol_version hs_state.hs_client_random hs_state.hs_server_random with *)
        (* TODO: here we should shred pms *)
        | Error (x,y) -> Error (x,y)
        | Correct (ms) ->
            let hs_state = {hs_state with next_ms = ms} in
            let certificateVerifyBytesResult =
                match hs_state.hs_next_info.clientID with
                | None ->
                    (* No client certificate ==> no certificateVerify message *)
                    correct ([||])
                | Some (cert) ->
                    if certificate_has_signing_capability cert then
                        let to_sign = hs_state.hs_msg_log @| clientCertBytes @| clientKEXBytes in
                        match clSpecState.must_send_cert with
                        | None -> unexpectedError "[prepare_output] If client sent a certificate, it must have been requested to."
                        | Some (certReqMsg) ->
                            makeCertificateVerifyBytes cert to_sign hs_state.hs_next_info.protocol_version certReqMsg
                    else
                        correct ([||])
            match certificateVerifyBytesResult with
            | Error (x,y) -> Error (x,y)
            | Correct (certificateVerifyBytes) ->
                (* Enqueue current messages *)
                let to_send = clientCertBytes @| clientKEXBytes @| certificateVerifyBytes in
                let new_outgoing = hs_state.hs_outgoing @| to_send in
                let new_log = hs_state.hs_msg_log @| to_send in
                let hs_state = {hs_state with hs_outgoing = new_outgoing
                                              hs_msg_log = new_log} in

                (* Handle CCS and Finished, including computation of session secrets *)
                match compute_session_secrets_and_CCSs hs_state CtoS with
                | Error (x,y) -> Error (x,y)
                | Correct (hs_state) ->
                    (* Now go for the creation of the Finished message *)
                    let ki = 
                        match hs_state.ccs_outgoing with
                        | None -> unexpectedError "[prepare_client_output_full] The current state should contain a valid outgoing KeyInfo"
                        | Some (_,ccs_data) -> ccs_data.ki
                    match makeFinishedMsgBytes ki hs_state.next_ms hs_state.hs_msg_log with
                    (* match makeFinishedMsgBytes sinfo.protocol_version sinfo.cipher_suite sinfo.more_info.mi_ms CtoS hs_state.hs_msg_log with *)
                    | Error (x,y) -> Error (x,y)
                    | Correct (result) ->
                        let (finishedBytes,cVerifyData) = result in
                        let new_out = hs_state.hs_outgoing_after_ccs @| finishedBytes in
                        let new_log = hs_state.hs_msg_log @| finishedBytes in
                        let hs_state = {hs_state with hs_outgoing_after_ccs = new_out
                                                      hs_msg_log = new_log
                                                      hs_renegotiation_info_cVerifyData = cVerifyData} in
                        correct (hs_state)

let prepare_client_output_resumption hs_state =
    let ki = 
        match hs_state.ccs_outgoing with
        | None -> unexpectedError "[prepare_client_output_resumption] The current state should contain a valid outgoing KeyInfo"
        | Some (_,ccs_data) -> ccs_data.ki
    match makeFinishedMsgBytes ki hs_state.next_ms hs_state.hs_msg_log with
    (* match makeFinishedMsgBytes sinfo.protocol_version sinfo.cipher_suite sinfo.more_info.mi_ms CtoS hs_state.hs_msg_log with *)
    | Error (x,y) -> Error (x,y)
    | Correct (result) ->
        let (finishedBytes,cVerifyData) = result in
        let new_out = hs_state.hs_outgoing_after_ccs @| finishedBytes in
        (* No need to log this message *)
        let hs_state = {hs_state with hs_outgoing_after_ccs = new_out
                                      hs_renegotiation_info_cVerifyData = cVerifyData} in
        correct (hs_state)

let init_handshake dir poptions =
    (* Start a new first session without resumption *)
    match dir with
    | CtoS ->
        let (cHelloBytes,client_random) = makeCHelloBytes poptions [||] [||] in
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
    let (cHelloBytes,client_random) = makeCHelloBytes poptions sid [||] in
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
            let (cHelloBytes,client_random) = makeCHelloBytes ops [||] state.hs_renegotiation_info_cVerifyData in
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
                        let (cHelloBytes,client_random) = makeCHelloBytes ops sid state.hs_renegotiation_info_cVerifyData in
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

let enqueue_fragment hs_state fragment =
    let new_inc = hs_state.hs_incoming @| fragment in
    {hs_state with hs_incoming = new_inc}

let parse_fragment hs_state =
    (* Inefficient but simple implementation:
       every time we reparse the whole incoming buffer,
       searching for a full packet. When a full packet is found,
       it is removed from the buffer. *)
    if length hs_state.hs_incoming < 4 then
        (* Not enough data to even start parsing *)
        (hs_state, None)
    else
        let (hstypeb,rem) = split hs_state.hs_incoming 1 in
        let (lenb,rem) = split rem 3 in
        let len = int_of_bytes lenb in
        if length rem < len then
            (* not enough payload, try next time *)
            (hs_state, None)
        else
            let hstype = hs_type_of_bytes hstypeb in
            let (payload,rem) = split rem len in
            let hs_state = { hs_state with hs_incoming = rem } in
            let to_log = hstypeb @| lenb @| payload in
            (hs_state, Some(hstype,payload,to_log))
        
let rec recv_fragment_client (hs_state:hs_state) (must_change_ver:ProtocolVersionType Option) =
    let (hs_state,new_packet) = parse_fragment hs_state in
    match new_packet with
    | None ->
      match must_change_ver with
      | None -> (correct (HSAck), hs_state)
      | Some (pv) -> (correct (HSChangeVersion(CtoS,pv)),hs_state)
    | Some (data) ->
      let (hstype,payload,to_log) = data in
      match hs_state.pstate with
      | Client(cState) ->
        match hstype with
        | HT_hello_request ->
            match cState with
            | CIdle -> (* This is a legitimate hello request. Properly handle it *)
                (* Do not log this message *)
                match hs_state.poptions.honourHelloReq with
                | HRPIgnore -> recv_fragment_client hs_state must_change_ver
                | HRPResume -> let hs_state = start_rekey hs_state hs_state.poptions in (correct (HSAck), hs_state) (* Terminating case, we reset all buffers *)
                | HRPFull -> let hs_state = start_rehandshake hs_state hs_state.poptions in (correct (HSAck), hs_state) (* Terminating case, we reset all buffers *)
            | _ -> (* RFC 7.4.1.1: ignore this message *) recv_fragment_client hs_state must_change_ver
        | HT_server_hello ->
            match cState with
            | ServerHello ->
                let (shello,server_random) = parseSHello payload in
                (* Sanity checks on the received message *)
                (* FIXME: are they security-relevant here? Or only functionality-relevant? *)
                
                (* Check that the server agreed version is between maxVer and minVer. *)
                if not (shello.server_version >= hs_state.poptions.minVer && shello.server_version <= hs_state.poptions.maxVer) then
                    (Error(HSError(AD_protocol_version),HSSendAlert),hs_state)
                else
                    (* Check that negotiated ciphersuite is in the allowed list. Note: if resuming a session, we still have
                    to check that this ciphersuite is the expected one! *)
                    if not (List.exists (fun x -> x = shello.cipher_suite) hs_state.poptions.ciphersuites) then
                        (Error(HSError(AD_illegal_parameter),HSSendAlert),hs_state)
                    else
                        (* Same for compression method *)
                        if not (List.exists (fun x -> x = shello.compression_method) hs_state.poptions.compressions) then
                            (Error(HSError(AD_illegal_parameter),HSSendAlert),hs_state)
                        else
                            (* Handling of safe renegotiation *)
                            let safe_reneg_result =
                                if hs_state.poptions.safe_renegotiation then
                                    let expected = hs_state.hs_renegotiation_info_cVerifyData @| hs_state.hs_renegotiation_info_sVerifyData in
                                    inspect_SHello_extensions shello.neg_extensions expected
                                else
                                    (* RFC Sec 7.4.1.4: with no safe renegotiation, we never send extensions; if the server sent any extension
                                       we MUST abot the handshake with unsupported_extension fatal alter (handled by the dispatcher) *)
                                    if not (equalBytes shello.neg_extensions [||]) then
                                        Error(HSError(AD_unsupported_extension),HSSendAlert)
                                    else
                                        let unitVal = () in
                                        correct (unitVal)
                            match safe_reneg_result with
                            | Error (x,y) -> (Error (x,y), hs_state)
                            | Correct _ ->
                                (* Log the received packet, and store the server random *)
                                let new_log = hs_state.hs_msg_log @| to_log in
                                let hs_state = {hs_state with hs_msg_log = new_log
                                                              ki_srand = server_random}
                                (* Check whether we asked for resumption *)
                                if isNullCipherSuite hs_state.hs_next_info.cipher_suite then
                                    (* we did not request resumption, do a full handshake *)
                                    (* define the sinfo we're going to establish *)
                                    let next_sinfo = { clientID = None
                                                       serverID = None
                                                       sessionID = if equalBytes shello.sh_session_id [||] then None else Some(shello.sh_session_id)
                                                       protocol_version = shello.server_version
                                                       cipher_suite = shello.cipher_suite
                                                       compression = shello.compression_method
                                                       init_crand = hs_state.hs_next_info.init_crand (* or, alternatively, hs_state.ki_crand *)
                                                       init_srand = server_random
                                                     } in
                                    let hs_state = {hs_state with hs_next_info = next_sinfo} in
                                    (* If DH_ANON, go into the ServerKeyExchange state, else go to the Certificate state *)
                                    if isAnonCipherSuite shello.cipher_suite then
                                        let hs_state = {hs_state with pstate = Client(ServerKeyExchange)} in
                                        recv_fragment_client hs_state (Some(shello.server_version))
                                    else
                                        let hs_state = {hs_state with pstate = Client(Certificate)} in
                                        recv_fragment_client hs_state (Some(shello.server_version))
                                else
                                    match hs_state.hs_next_info.sessionID with
                                    | None -> unexpectedError "[recv_fragment] A resumed session should never have empty SID"
                                    | Some(sid) ->
                                        if sid = shello.sh_session_id then (* use resumption *)
                                            (* Check that protocol version, ciph_suite and compression method are indeed the correct ones *)
                                            if hs_state.hs_next_info.protocol_version = shello.server_version then
                                                if hs_state.hs_next_info.cipher_suite = shello.cipher_suite then
                                                    if hs_state.hs_next_info.compression = shello.compression_method then
                                                        match compute_session_secrets_and_CCSs hs_state CtoS with
                                                        | Error (x,y) -> (Error  (x,y),hs_state)
                                                        | Correct (hs_state) ->
                                                            let clSpecState = { resumed_session = true;
                                                                                must_send_cert = None;
                                                                                client_certificate = None} in
                                                            let hs_state = { hs_state with pstate = Client(CCCS(clSpecState))}
                                                            recv_fragment_client hs_state (Some(shello.server_version))
                                                    else (Error(HSError(AD_illegal_parameter),HSSendAlert),hs_state)
                                                else (Error(HSError(AD_illegal_parameter),HSSendAlert),hs_state)
                                            else (Error(HSError(AD_illegal_parameter),HSSendAlert),hs_state)
                                        else (* server did not agreed on resumption, do a full handshake *)
                                            (* define the sinfo we're going to establish *)
                                            let next_sinfo = { clientID = None
                                                               serverID = None
                                                               sessionID = if equalBytes shello.sh_session_id [||] then None else Some(shello.sh_session_id)
                                                               protocol_version = shello.server_version
                                                               cipher_suite = shello.cipher_suite
                                                               compression = shello.compression_method
                                                               init_crand = hs_state.hs_next_info.init_crand (* or, alternatively, hs_state.ki_crand *)
                                                               init_srand = server_random
                                                               } in
                                            let hs_state = {hs_state with hs_next_info = next_sinfo} in
                                            (* If DH_ANON, go into the ServerKeyExchange state, else go to the Certificate state *)
                                            if isAnonCipherSuite shello.cipher_suite then
                                                let hs_state = {hs_state with pstate = Client(ServerKeyExchange)} in
                                                recv_fragment_client hs_state (Some(shello.server_version))
                                            else
                                                let hs_state = {hs_state with pstate = Client(Certificate)} in
                                                recv_fragment_client hs_state (Some(shello.server_version))
            | _ -> (* ServerHello arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
        | HT_certificate ->
            match cState with
            | Certificate ->
                match parseCertificate payload with
                | Error(x,y) -> (Error(x,y),hs_state)
                | Correct(certMsg) ->
                    if not (hs_state.poptions.certificateValidationPolicy certMsg.certificate_list) then
                        (Error(HSError(AD_bad_certificate),HSSendAlert),hs_state)
                    else (* We have validated server identity *)
                        (* Log the received packet *)
                        let new_log = hs_state.hs_msg_log @| to_log in
                        let hs_state = {hs_state with hs_msg_log = new_log} in           
                        (* update the sinfo we're establishing *)
                        let next_sinfo = {hs_state.hs_next_info with serverID = Some(certMsg.certificate_list.Head)} in
                        let hs_state = {hs_state with hs_next_info = next_sinfo} in
                        if cipherSuiteRequiresKeyExchange hs_state.hs_next_info.cipher_suite then
                            let hs_state = {hs_state with pstate = Client(ServerKeyExchange)} in
                            recv_fragment_client hs_state must_change_ver
                        else
                            let hs_state = {hs_state with pstate = Client(CertReqOrSHDone)} in
                            recv_fragment_client hs_state must_change_ver
            | _ -> (* Certificate arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
        | HT_server_key_exchange ->
            match cState with
            | ServerKeyExchange ->
                (* TODO *) (Error(HSError(AD_internal_error),HSSendAlert),hs_state)
            | _ -> (* Server Key Exchange arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
        | HT_certificate_request ->
            match cState with
            | CertReqOrSHDone ->
                (* Log the received packet *)
                let new_log = hs_state.hs_msg_log @| to_log in
                let hs_state = {hs_state with hs_msg_log = new_log} in

                (* Note: in next statement, use next_info, because the handshake runs according to the session we want to
                   establish, not the current one *)
                match parseCertReq hs_state.hs_next_info.protocol_version payload with
                | Error(x,y) -> (Error(x,y),hs_state)
                | Correct(certReqMsg) ->
                let client_cert = find_client_cert certReqMsg in
                (* Update the sinfo we're establishing *)
                let next_info = {hs_state.hs_next_info with clientID =
                                                            match client_cert with
                                                            | None -> None
                                                            | Some(certList) -> Some(certList.Head)} in
                let hs_state = {hs_state with hs_next_info = next_info} in
                let clSpecState = {resumed_session = false;
                                   must_send_cert = Some(certReqMsg);
                                   client_certificate = client_cert} in
                let hs_state = {hs_state with pstate = Client(CSHDone(clSpecState))} in
                recv_fragment_client hs_state must_change_ver
            | _ -> (* Certificate Request arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
        | HT_server_hello_done ->
            match cState with
            | CertReqOrSHDone ->
                if not (equalBytes payload [||]) then
                    (Error(HSError(AD_decode_error),HSSendAlert),hs_state)
                else
                    (* Log the received packet *)
                    let new_log = hs_state.hs_msg_log @| to_log in
                    let hs_state = {hs_state with hs_msg_log = new_log} in

                    let clSpecState = {
                        resumed_session = false;
                        must_send_cert = None;
                        client_certificate = None} in
                    match prepare_client_output_full hs_state clSpecState with
                    | Error (x,y) -> (Error (x,y), hs_state)
                    | Correct (hs_state) ->
                        let hs_state = {hs_state with pstate = Client(CCCS(clSpecState))}
                        recv_fragment_client hs_state must_change_ver
            | CSHDone(clSpecState) ->
                if not (equalBytes payload [||]) then
                    (Error(HSError(AD_decode_error),HSSendAlert),hs_state)
                else
                    (* Log the received packet *)
                    let new_log = hs_state.hs_msg_log @| to_log in
                    let hs_state = {hs_state with hs_msg_log = new_log} in

                    match prepare_client_output_full hs_state clSpecState with
                    | Error (x,y) -> (Error (x,y), hs_state)
                    | Correct (hs_state) ->
                        let hs_state = {hs_state with pstate = Client(CCCS(clSpecState))}
                        recv_fragment_client hs_state must_change_ver
            | _ -> (* Server Hello Done arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
        | HT_finished ->
            match cState with
            | CFinished (clSpState) ->
                (* Check received content *)
                let ki =
                    match hs_state.ccs_incoming with
                    | None -> unexpectedError "[recv_fragment_client] ccs_incoming should have some value when in CFinished state"
                    | Some (ccs_data) -> ccs_data.ki
                match checkVerifyData ki hs_state.next_ms hs_state.hs_msg_log payload with
                | Error (x,y) -> (Error(x,y),hs_state)
                | Correct(verifyDataisOK) ->
                    if not verifyDataisOK then
                        (Error(HSError(AD_decrypt_error),HSSendAlert),hs_state)
                    else
                        (* Store server verifyData, in case we use safe resumption *)
                        let hs_state = {hs_state with hs_renegotiation_info_sVerifyData = payload} in
                        if clSpState.resumed_session then
                            (* Log the received message *)
                            let new_log = hs_state.hs_msg_log @| to_log in
                            let hs_state = {hs_state with hs_msg_log = new_log} in
                            match prepare_client_output_resumption hs_state with
                            | Error (x,y) -> (Error (x,y), hs_state)
                            | Correct (hs_state) ->
                                let hs_state = {hs_state with pstate = Client(CWatingToWrite)} in
                                (correct (HSReadSideFinished),hs_state)
                        else    
                            (* Handshake fully completed successfully. Report this fact to the dispatcher:
                                it will take care of moving the handshake to the Idle state, updating the sinfo with the
                                one we've been creating in this handshake. *)
                            (* Note: no need to log this message *)
                            let storableSession = { sinfo = hs_state.hs_next_info;
                                                    ms = hs_state.next_ms;
                                                    dir = CtoS}
                            (correct (HSFullyFinished_Read (storableSession)),hs_state)
            | _ -> (* Finished arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
        | _ -> (* Unsupported/Wrong message *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
      
      (* Should never happen *)
      | Server(_) -> unexpectedError "[recv_fragment_client] should only be invoked when in client role."

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

let prepare_server_output_full hs_state maxClVer =
    let ext_data = hs_state.hs_renegotiation_info_cVerifyData @| hs_state.hs_renegotiation_info_sVerifyData in
    let (sHelloB,sRandom) = makeSHelloBytes hs_state.poptions hs_state.hs_next_info ext_data in
    let next_info = {hs_state.hs_next_info with init_srand = sRandom} in
    let hs_state = {hs_state with hs_next_info = next_info
                                  ki_srand = sRandom} in
    let res =
        if isAnonCipherSuite hs_state.hs_next_info.cipher_suite then
            correct ([||],hs_state)
        else
            match getServerCert hs_state.hs_next_info.cipher_suite hs_state.poptions with
            | Error(x,y) -> Error(x,y)
            | Correct(sCert) ->
                (* update server identity in the sinfo *)
                let next_info = {hs_state.hs_next_info with serverID = Some(sCert)} in
                let hs_state = {hs_state with hs_next_info = next_info} in
                correct (makeCertificateBytes (Some([sCert])), hs_state)
    match res with
    | Error(x,y) -> Error(x,y)
    | Correct (res) ->
        let (certificateB,hs_state) = res in
        let res =
            if isAnonCipherSuite hs_state.hs_next_info.cipher_suite || cipherSuiteRequiresKeyExchange hs_state.hs_next_info.cipher_suite then
                (* TODO: DH key exchange *)
                Error(HSError(AD_internal_error),HSSendAlert)
            else
                correct ([||])
        match res with
        | Error(x,y) -> Error(x,y)
        | Correct (serverKeyExchangeB) ->
            let certificateRequestB =
                if hs_state.poptions.request_client_certificate then
                    makeCertificateRequestBytes hs_state.hs_next_info.cipher_suite hs_state.hs_next_info.protocol_version
                else
                    [||]
            let sHelloDoneB = makeSHelloDoneBytes () in
            let output = sHelloB @| certificateB @| serverKeyExchangeB @| certificateRequestB @| sHelloDoneB in
            (* Log the output and put it into the output buffer *)
            let new_log = hs_state.hs_msg_log @| output in
            let new_out = hs_state.hs_outgoing @| output in
            let hs_state = {hs_state with hs_msg_log = new_log
                                          hs_outgoing = new_out} in
            (* Compute the next state of the server *)
            let sSpecSt = { resumed_session = false
                            highest_client_ver = maxClVer} in
            let hs_state =
                if hs_state.poptions.request_client_certificate then
                    {hs_state with pstate = Server(ClCert(sSpecSt))}
                else
                    {hs_state with pstate = Server(ClientKEX(sSpecSt))}
            correct (hs_state)

let start_server_full hs_state cHello =
    (* Negotiate the protocol parameters *)
    match enum<ProtocolVersionType>(System.Math.Min (int cHello.client_version, int hs_state.poptions.maxVer)) with
    | negPV when negPV >= ProtocolVersionType.SSL_3p0 ->
        match negotiate cHello.cipher_suites hs_state.poptions.ciphersuites with
        | None -> Error(HSError(AD_handshake_failure),HSSendAlert)
        | Some(negCS) ->
            match negotiate cHello.compression_methods hs_state.poptions.compressions with
            | None -> Error(HSError(AD_handshake_failure),HSSendAlert)
            | Some(negCM) ->
                (* TODO: now we don't support safe_renegotiation, and we ignore any client proposed extension *)
                let sid = OtherCrypto.mkRandom 32 in
                (* Fill in the session info we're establishing *)
                let next_info = { clientID = None
                                  serverID = None
                                  sessionID = Some(sid)
                                  protocol_version = negPV
                                  cipher_suite = negCS
                                  compression = negCM
                                  init_crand = hs_state.ki_crand
                                  init_srand = [||]
                                }
                let hs_state = {hs_state with hs_next_info = next_info} in
                match prepare_server_output_full hs_state cHello.client_version with
                | Error(x,y) -> Error(x,y)
                | Correct(hs_state) -> correct ((hs_state,negPV))
    | _ -> Error(HSError(AD_handshake_failure),HSSendAlert)

let prepare_server_output_resumption hs_state =
    let ext_data = hs_state.hs_renegotiation_info_cVerifyData @| hs_state.hs_renegotiation_info_sVerifyData in
    let (sHelloB,sRandom) = makeSHelloBytes hs_state.poptions hs_state.hs_next_info ext_data in
    let hs_state = {hs_state with ki_srand = sRandom} in
    let new_out = hs_state.hs_outgoing @| sHelloB in
    let new_log = hs_state.hs_msg_log @| sHelloB in
    let hs_state = {hs_state with hs_outgoing = new_out
                                  hs_msg_log = new_log} in
    match compute_session_secrets_and_CCSs hs_state StoC with
    | Error(x,y) -> Error(x,y)
    | Correct (hs_state) ->
        let ki =
            match hs_state.ccs_outgoing with
            | None -> unexpectedError "[prepare_server_output_resumption] The ccs_outgoing buffer should contain some value when computing the finished message"
            | Some (_,ccs_data) -> ccs_data.ki
        match makeFinishedMsgBytes ki hs_state.next_ms hs_state.hs_msg_log with
        (* match makeFinishedMsgBytes sinfo.protocol_version sinfo.cipher_suite sinfo.more_info.mi_ms StoC hs_state.hs_msg_log with *)
        | Error(x,y) -> Error(x,y)
        | Correct(finishedB,verifyData) ->
            let new_out = hs_state.hs_outgoing_after_ccs @| finishedB in
            let new_log = hs_state.hs_msg_log @| finishedB in
            let sSpecState = {resumed_session = true
                              highest_client_ver = hs_state.hs_next_info.protocol_version} (* Highest version is useless with resumption. We already agree on the MS *)
            let hs_state = {hs_state with hs_outgoing_after_ccs = new_out
                                          hs_msg_log = new_log
                                          hs_renegotiation_info_sVerifyData = verifyData
                                          pstate = Server(SCCS(sSpecState))} in
            correct(hs_state)

let rec recv_fragment_server (hs_state:hs_state) (must_change_ver:ProtocolVersionType Option) =
    let (hs_state,new_packet) = parse_fragment hs_state in
    match new_packet with
    | None ->
      match must_change_ver with
      | None -> (correct (HSAck), hs_state)
      | Some (pv) -> (correct (HSChangeVersion(StoC,pv)),hs_state)
    | Some (data) ->
      let (hstype,payload,to_log) = data in
      match hs_state.pstate with
      | Server(sState) ->
        match hstype with
        | HT_client_hello ->
            match sState with
            | x when x = ClientHello || x = SIdle ->
                let (cHello,cRandom) = parseCHello payload in
                let hs_state = {hs_state with ki_crand = cRandom} in
                (* Log the received message *)
                let new_log = hs_state.hs_msg_log @| to_log in
                let hs_state = {hs_state with hs_msg_log = new_log} in
                (* Handling of renegotiation_info extenstion *)
                let extRes =
                    if hs_state.poptions.safe_renegotiation then
                        if check_client_renegotiation_info cHello hs_state.hs_renegotiation_info_cVerifyData then
                            correct(hs_state)
                        else
                            (* We don't accept an insecure client *)
                            Error(HSError(AD_handshake_failure),HSSendAlert)
                    else
                        (* We can ignore the extension, if any *)
                        correct(hs_state)
                match extRes with
                | Error(x,y) -> (Error(x,y),hs_state)
                | Correct(hs_state) ->
                    (* Check whether the client asked for session resumption *)
                    if equalBytes cHello.ch_session_id [||] then
                        (* Client did not ask for resumption. Do a full Handshake *)
                        match start_server_full hs_state cHello with
                        | Error(x,y) -> (Error(x,y),hs_state)
                        | Correct(res) ->
                            let (hs_state,negPV) = res in
                            recv_fragment_server hs_state (Some(negPV))
                    else
                        (* Client asked for resumption, let's see if we can satisfy the request *)
                        (* FIXME: this SessionDB interaction seems right to be here, however, I'd like to move
                           all SessionDB in the Dispatch. (Why in the Dispatcher? Not sure) *)
                        match select hs_state.poptions cHello.ch_session_id with
                        | None ->
                            (* We don't have the requested session stored, go for a full handshake *)
                            match start_server_full hs_state cHello with
                            | Error(x,y) -> (Error(x,y),hs_state)
                            | Correct(res) ->
                                let (hs_state,negPV) = res in
                                recv_fragment_server hs_state (Some(negPV))
                        | Some (storedSession) ->
                            (* Check client proposed algorithms match with our stored session *)
                            match storedSession.dir with
                            | CtoS -> (* This session is not for us, we're a server. Do full handshake *)
                                match start_server_full hs_state cHello with
                                | Error(x,y) -> (Error(x,y),hs_state)
                                | Correct(res) ->
                                    let (hs_state,negPV) = res in
                                    recv_fragment_server hs_state (Some(negPV))
                            | StoC ->
                                if cHello.client_version >= storedSession.sinfo.protocol_version then
                                    (* We have a common version *)
                                    if not (List.exists (fun cs -> cs = storedSession.sinfo.cipher_suite) cHello.cipher_suites) then
                                        (* Do a full handshake *)
                                        match start_server_full hs_state cHello with
                                        | Error(x,y) -> (Error(x,y),hs_state)
                                        | Correct(res) ->
                                            let (hs_state,negPV) = res in
                                            recv_fragment_server hs_state (Some(negPV))
                                    else
                                        if not (List.exists (fun cm -> cm = storedSession.sinfo.compression) cHello.compression_methods) then
                                            (* Do a full handshake *)
                                            match start_server_full hs_state cHello with
                                            | Error(x,y) -> (Error(x,y),hs_state)
                                            | Correct(res) ->
                                                let (hs_state,negPV) = res in
                                                recv_fragment_server hs_state (Some(negPV))
                                        else
                                            (* Everything is ok, proceed with resumption *)
                                            let hs_state = {hs_state with hs_next_info = storedSession.sinfo
                                                                          next_ms = storedSession.ms}
                                            match prepare_server_output_resumption hs_state with
                                            | Error(x,y) -> (Error(x,y), hs_state)
                                            | Correct(hs_state) ->
                                                recv_fragment_server hs_state (Some(storedSession.sinfo.protocol_version))
                                else
                                    (* Do a full handshake *)
                                    match start_server_full hs_state cHello with
                                    | Error(x,y) -> (Error(x,y),hs_state)
                                    | Correct(res) ->
                                        let (hs_state,negPV) = res in
                                        recv_fragment_server hs_state (Some(negPV))
            | _ -> (* Message arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
        | HT_certificate ->
            match sState with
            | ClCert (sSpecSt) ->
                match parseCertificate payload with
                | Error(x,y) -> (Error(x,y),hs_state)
                | Correct(certMsg) ->
                    if not (hs_state.poptions.certificateValidationPolicy certMsg.certificate_list) then
                        (Error(HSError(AD_bad_certificate),HSSendAlert),hs_state)
                    else (* We have validated client identity *)
                        (* Log the received packet *)
                        let new_log = hs_state.hs_msg_log @| to_log in
                        let hs_state = {hs_state with hs_msg_log = new_log} in           
                        (* update the sinfo we're establishing *)
                        let next_info =
                            if certMsg.certificate_list.IsEmpty then
                                {hs_state.hs_next_info with clientID = None}
                            else
                                {hs_state.hs_next_info with clientID = Some(certMsg.certificate_list.Head)}
                        let hs_state = {hs_state with hs_next_info = next_info} in
                        (* move to the next state *)
                        let hs_state = {hs_state with pstate = Server(ClientKEX(sSpecSt))} in
                        recv_fragment_server hs_state must_change_ver
            | _ -> (* Message arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
        | HT_client_key_exchange ->
            match sState with
            | ClientKEX(sSpecSt) ->
                match parseClientKEX hs_state.hs_next_info sSpecSt hs_state.poptions payload with
                | Error(x,y) -> (Error(x,y),hs_state)
                | Correct(pms) ->
                    (* Log the received packet *)
                    let new_log = hs_state.hs_msg_log @| to_log in
                    let hs_state = {hs_state with hs_msg_log = new_log} in
                    match prfMS hs_state.hs_next_info pms with
                    (* assert: hs_state.hs_next_info.{c,s}rand = hs_state.ki_{c,s}rand *)
                    (* match compute_master_secret pms sinfo.more_info.mi_protocol_version hs_state.hs_client_random hs_state.hs_server_random with *)
                    (* TODO: here we should shred pms *)
                    | Error(x,y) -> (Error(x,y),hs_state)
                    | Correct(ms) ->
                        let hs_state = {hs_state with next_ms = ms} in
                        match compute_session_secrets_and_CCSs hs_state StoC with
                        | Error(x,y) -> (Error(x,y),hs_state)
                        | Correct(hs_state) ->
                            (* move to new state *)
                            match hs_state.hs_next_info.clientID with
                            | None -> (* No client certificate, so there will be no CertificateVerify message *)
                                let hs_state = {hs_state with pstate = Server(SCCS(sSpecSt))} in
                                recv_fragment_server hs_state must_change_ver
                            | Some(cert) ->
                                if certificate_has_signing_capability cert then
                                    let hs_state = {hs_state with pstate = Server(CertificateVerify(sSpecSt))} in
                                    recv_fragment_server hs_state must_change_ver
                                else
                                    let hs_state = {hs_state with pstate = Server(SCCS(sSpecSt))} in
                                    recv_fragment_server hs_state must_change_ver
            | _ -> (* Message arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
        | HT_certificate_verify ->
            match sState with
            | CertificateVerify(sSpecSt) ->
                match hs_state.hs_next_info.clientID with
                | None -> (* There should always be a client certificate in this state *)(Error(HSError(AD_internal_error),HSSendAlert),hs_state)
                | Some(clCert) ->
                    match certificateVerifyCheck hs_state payload with
                    | Error(x,y) -> (Error(x,y),hs_state)
                    | Correct(verifyOK) ->
                        if verifyOK then
                            (* Log the message *)
                            let new_log = hs_state.hs_msg_log @| to_log in
                            let hs_state = {hs_state with hs_msg_log = new_log} in   
                            (* move to next state *)
                            let hs_state = {hs_state with pstate = Server(SCCS(sSpecSt))} in
                            recv_fragment_server hs_state must_change_ver
                        else
                            (Error(HSError(AD_decrypt_error),HSSendAlert),hs_state)
            | _ -> (* Message arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
        | HT_finished ->
            match sState with
            | SFinished(sSpecSt) ->
                let kiIn =
                    match hs_state.ccs_incoming with
                    | None -> unexpectedError "[recv_fragment_server] the incoming KeyInfo should be set now"
                    | Some (ccs_data) -> ccs_data.ki
                match checkVerifyData kiIn hs_state.next_ms hs_state.hs_msg_log payload with
                (* match checkVerifyData sinfo.protocol_version sinfo.cipher_suite sinfo.more_info.mi_ms CtoS hs_state.hs_msg_log payload with *)
                | Error (x,y) -> (Error(x,y),hs_state)
                | Correct(verifyDataisOK) ->
                    if not verifyDataisOK then
                        (Error(HSError(AD_decrypt_error),HSSendAlert),hs_state)
                    else
                        (* Save client verify data to possibly use it in the renegotiation_info extension *)
                        let hs_state = {hs_state with hs_renegotiation_info_cVerifyData = payload} in
                        if sSpecSt.resumed_session then
                            (* Handshake fully completed successfully. Report this fact to the dispatcher:
                                it will take care of moving the handshake to the Idle state, updating the sinfo with the
                                one we've been creating in this handshake. *)
                            (* Note: no need to log this message *)
                            let storableSession = { sinfo = hs_state.hs_next_info
                                                    ms = hs_state.next_ms
                                                    dir = StoC}
                            (correct (HSFullyFinished_Read (storableSession)),hs_state)
                        else
                            (* Log the received message *)
                            let new_log = hs_state.hs_msg_log @| to_log in
                            let hs_state = {hs_state with hs_msg_log = new_log} in
                            let kiOut =
                                match hs_state.ccs_outgoing with
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
                            match makeFinishedMsgBytes kiOut hs_state.next_ms hs_state.hs_msg_log with
                            (* match makeFinishedMsgBytes sinfo.protocol_version sinfo.cipher_suite sinfo.more_info.mi_ms StoC hs_state.hs_msg_log with *)
                            | Error(x,y) -> (Error(x,y),hs_state)
                            | Correct(packet,verifyData) ->
                                let new_out = hs_state.hs_outgoing_after_ccs @| packet in
                                let hs_state = {hs_state with hs_outgoing_after_ccs = new_out
                                                              hs_renegotiation_info_sVerifyData = verifyData
                                                              pstate = Server(SWaitingToWrite)} in
                                (correct (HSReadSideFinished),hs_state)                                
            | _ -> (* Message arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
        | _ -> (* Unsupported/Wrong message *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
      (* Should never happen *)
      | Client(_) -> unexpectedError "[recv_fragment_server] should only be invoked when in server role."

let recv_fragment (hs_state:hs_state) (tlen:int) (fragment:fragment) =
    (* Note, we receive fragments in the current session, not the one we're establishing *)
    (* FIXME: This session might be wrong, in the CCS/Finished/FullyFinished(Idle) transition. But we don't care now *)
    let fragment = pub_fragment_to_bytes hs_state.hs_cur_info tlen fragment in
    let hs_state = enqueue_fragment hs_state fragment in
    match hs_state.pstate with
    | Client (_) -> recv_fragment_client hs_state None
    | Server (_) -> recv_fragment_server hs_state None

let recv_ccs (hs_state: hs_state) (tlen:int) (fragment:fragment): ((ccs_data Result) * hs_state) =
    (* Some parsing *)
    let fragment = pub_fragment_to_bytes hs_state.hs_cur_info tlen fragment in
    if length fragment <> 1 then
        (Error(HSError(AD_decode_error),HSSendAlert),hs_state)
    else
        if (int_of_bytes fragment) <> 1 then
            (Error(HSError(AD_decode_error),HSSendAlert),hs_state)
        else
            (* CCS is good *)
            match hs_state.pstate with
            | Client (cstate) ->
                (* Check we are in the right state (CCCS) *)
                match cstate with
                | CCCS (clSpState) ->
                    match hs_state.ccs_incoming with
                    | None -> unexpectedError "[recv_ccs] when in CCCS state, ccs_incoming should have some value."
                    | Some (ccs_result) ->
                        let hs_state = {hs_state with (* ccs_incoming = None *) (* Don't reset its value now. We'll need it when computing the other side Finished message *)
                                                      pstate = Client (CFinished (clSpState))} in
                        (correct(ccs_result),hs_state)
                | _ -> (* CCS arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
            | Server (sState) ->
                match sState with
                | SCCS (sSpecSt) ->
                    match hs_state.ccs_incoming with
                    | None -> unexpectedError "[recv_ccs] when in CCCS state, ccs_incoming should have some value."
                    | Some (ccs_result) ->
                        let hs_state = {hs_state with (* ccs_incoming = None *) (* Don't reset its value now. We'll need it when computing the other side Finished message *)
                                                      pstate = Server(SFinished(sSpecSt))} in
                        (correct(ccs_result),hs_state)
                | _ -> (* CCS arrived in the wrong state *) (Error(HSError(AD_unexpected_message),HSSendAlert),hs_state)
