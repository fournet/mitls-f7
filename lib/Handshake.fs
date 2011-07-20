(* Handshake protocol *) 
module Handshake

open Data
open Bytearray
open Record
open Error_handling
open Formats
open HS_msg
open HS_ciphersuites
open Sessions
open CryptoTLS
open AppCommon
open Principal

type clientSpecificState =
    { resumed_session: bool
      must_send_cert: certificateRequest Option
      client_certificate: (pri_cert list) Option
    }

type clientState =
    | ServerHello of SessionInfo Option (* client proposed session to be resumed, useful to check wether we're going to do resumption or full negotiation *)
    | Certificate of SessionInfo (* the session we're creating *)
    | ServerKeyExchange of SessionInfo (* Same as above *)
    | CertReqOrSHDone of SessionInfo (* Same as above *)
    | CSHDone of SessionInfo * clientSpecificState
    | CCCS of SessionInfo * clientSpecificState
    | CFinished of SessionInfo * clientSpecificState
    | CIdle

type serverState =
    | ClientHello
    | Keying
    | ClientKEX
    | CertificateVerify
    | SCCS
    | SFinished
    | SIdle

type protoState =
    | Client of clientState
    | Server of serverState

type pre_hs_state = {
  hs_outgoing    : bytes (* outgiong data before a ccs *)
  ccs_outgoing: (bytes * ccs_data) option (* marker telling there's a ccs ready *)
  hs_outgoing_after_ccs: bytes (* data to be sent after the ccs has been sent *)
  hs_incoming    : bytes (* partial incoming HS message *)
  hs_info : SessionInfo;
  poptions: protocolOptions;
  pstate : protoState
  hs_msg_log: bytes
  hs_client_random: bytes
  hs_server_random: bytes
}

type hs_state = pre_hs_state

type HSFragReply =
  | EmptyHSFrag
  | HSFrag of bytes
  | HSWriteSideFinished
  | HSFullyFinished_Write of SessionInfo
  | CCSFrag of bytes * ccs_data

let get_next_bytes data frag_len =
    if frag_len >= length data then
        (data,empty_bstr)
    else
        split data frag_len

let next_fragment state len =
    (* FIXME: The buffer we read from should depend on the state of the protocol,
       and not on whether a buffer is full or not, otherwise we cannot recognize the
       HSNewSessionInfo() case! *)
    match state.hs_outgoing with
    | x when equalBytes x empty_bstr ->
        match state.ccs_outgoing with
        | None -> (EmptyHSFrag, state)
        | Some x ->
            let (ccs,ciphsuite) = x in
            let new_hs_outgoing = state.hs_outgoing_after_ccs in
            let state = {state with hs_outgoing = new_hs_outgoing;
                                    ccs_outgoing = None;
                                    hs_outgoing_after_ccs = empty_bstr}
            (CCSFrag (ccs,ciphsuite), state)
    | d ->
        let (f,rem) = get_next_bytes d len in
        let state = {state with hs_outgoing = rem} in
        (HSFrag(f),state)

type recv_reply = 
  | HSAck      (* fragment accepted, no visible effect so far *)
  | HSChangeVersion of role * ProtocolVersionType 
                          (* ..., and we should use this new protocol version for sending *) 
  | HSReadSideFinished
  | HSFullyFinished_Read of SessionInfo (* ..., and we can start sending data on the connection *)

let makeHSPacket ht data =
    let htb = bytes_of_hs_type ht in
    let len = length data in
    let blen = bytes_of_int 3 len in
    appendList [htb; blen; data]

let makeHelloRequestBytes () =
    makeHSPacket HT_hello_request empty_bstr

let makeTimestamp () = (* FIXME: we may need to abstract this function *)
    let t = (System.DateTime.UtcNow - new System.DateTime(1970, 1, 1))
    (int) t.TotalSeconds

let makeCHello poptions session =
    let random = { time = makeTimestamp ();
                   rnd = Crypto.mkRandom 28} in
    {
    client_version = poptions.maxVer
    ch_random = random
    ch_session_id = session
    cipher_suites = poptions.ciphersuites
    compression_methods = poptions.compressions
    extensions = empty_bstr
    }

let rec b_of_cslist cslist acc =
    match cslist with
    | [] -> vlenBytes_of_bytes 2 acc
    | h::t ->
        let csb = bytes_of_cipherSuite h in
        let acc = append acc csb in
        b_of_cslist t acc

let bytes_of_cipherSuites cslist =
    b_of_cslist cslist empty_bstr

let rec b_of_complist complist acc =
    match complist with
    | [] -> vlenBytes_of_bytes 1 acc
    | h::t ->
        let compb = bytes_of_compression h in
        let acc = append acc compb in
        b_of_complist t acc

let bytes_of_compressionMethods complist =
    b_of_complist complist empty_bstr

let makeCHelloBytes poptions session =
    let cHello = makeCHello poptions session in
    let cVerB = bytes_of_protocolVersionType cHello.client_version in
    let tsbytes = bytes_of_int 4 cHello.ch_random.time in
    let random = append tsbytes cHello.ch_random.rnd in
    let csessB = vlenBytes_of_bytes 1 cHello.ch_session_id in
    let ccsuitesB = bytes_of_cipherSuites cHello.cipher_suites in
    let ccompmethB = bytes_of_compressionMethods cHello.compression_methods in
    let data = appendList [cVerB; random; csessB; ccsuitesB; ccompmethB; cHello.extensions] in
    ((makeHSPacket HT_client_hello data),random)

let bytes_of_certificates certList =
    let certListB = List.map bytes_of_certificate certList in
    appendList certListB

let makeCertificateBytes certOpt =
    match certOpt with
    | None ->
        let data = vlenBytes_of_bytes 3 empty_bstr in
        makeHSPacket HT_certificate data
    | Some(certList) ->
        let pre_data = bytes_of_certificates certList in
        let data = vlenBytes_of_bytes 3 pre_data in
        makeHSPacket HT_certificate data

let makeClientKEXBytes hs_state clSpecInfo sinfo =
    if canEncryptPMS sinfo.more_info.mi_cipher_suite then
        let verBytes = bytes_of_protocolVersionType hs_state.poptions.maxVer in
        let rnd = Crypto.mkRandom 46 in
        let pms = append verBytes rnd in
        match sinfo.serverID with
        | None -> unexpectedError "[makeClientKEXBytes] Server certificate should always be present with a RSA signing cipher suite."
        | Some (serverCert) ->
            let pubKey = pubKey_of_certificate serverCert in
            match rsa_encrypt pubKey pms with
            | Error (x,y) -> Error (HandshakeProto,Internal)
            | Correct (encpms) ->
                if sinfo.more_info.mi_protocol_version = ProtocolVersionType.SSL_3p0 then
                    correct (makeHSPacket HT_client_key_exchange encpms)
                else
                    let encpms = vlenBytes_of_bytes 2 encpms in
                    correct (makeHSPacket HT_client_key_exchange encpms)
    else
        match clSpecInfo.must_send_cert with
        | Some (_) ->
            match sinfo.clientID with
            | None -> (* Client certificate not sent, (and not in RSA mode)
                         so we must use DH parameters *)
                (* TODO: send public Yc value *)
                let ycBytes = empty_bstr in
                correct (makeHSPacket HT_client_key_exchange ycBytes)
            | Some (cert) ->
                (* TODO: check whether the certificate already contained suitable DH parameters *)
                correct (makeHSPacket HT_client_key_exchange empty_bstr)
        | None ->
            (* Use DH parameters *)
            let ycBytes = empty_bstr in
            correct (makeHSPacket HT_client_key_exchange ycBytes)

let hashNametoFun hn =
    match hn with
    | HashAlg.HA_md5 -> correct (md5)
    | HashAlg.HA_sha1 -> correct (sha1)
    | HashAlg.HA_sha224 -> Error (HandshakeProto,Unsupported)
    | HashAlg.HA_sha256 -> correct (sha256)
    | HashAlg.HA_sha384 -> correct (sha384)
    | HashAlg.HA_sha512 -> correct (sha512)
    | _ -> Error (HandshakeProto,Unsupported)

let makeCertificateVerifyBytes cert data pv certReqMsg=
    let priKey = priKey_of_certificate cert in
    match pv with
    | ProtocolVersionType.TLS_1p2 ->
        (* If DSA, use SHA-1 hash *)
        if certificate_is_dsa cert then (* TODO *)
            (*let hash = sha1 data in
            let signed = dsa_sign priKey hash in *)
            correct (empty_bstr)
        else
            (* Get server preferred hash algorithm *)
            let hashAlg =
                match certReqMsg.signature_and_hash_algorithm with
                | None -> unexpectedError "[makeCertificateVerifyBytes] We are in TLS 1.2, so the server should send a SigAndHashAlg structure."
                | Some (sahaList) -> sahaList.Head.SaHA_hash
            match hashNametoFun hashAlg with
            | Error (x,y) -> Error (x,y)
            | Correct (hFun) ->
                match hFun data with
                | Error (x,y) -> Error (HandshakeProto, Internal)
                | Correct (hashed) ->
                    match rsa_encrypt priKey hashed with
                    | Error (x,y) -> Error (HandshakeProto, Internal)
                    | Correct (signed) ->
                        let signed = vlenBytes_of_bytes 2 signed in
                        let hashAlgBytes = bytes_of_int 1 (int hashAlg) in
                        let signAlgBytes = bytes_of_int 1 (int SigAlg.SA_rsa) in
                        let payload = appendList [hashAlgBytes;signAlgBytes;signed] in
                        correct (makeHSPacket HT_certificate_verify payload)
    | x when x = ProtocolVersionType.TLS_1p0 || x = ProtocolVersionType.TLS_1p1 ->
        (* TODO *) Error (HandshakeProto,Unsupported)
    | ProtocolVersionType.SSL_3p0 ->
        (* TODO *) Error (HandshakeProto,Unsupported)
    | _ -> Error (HandshakeProto,Unsupported)

let compute_master_secret pms ver crandom srandom = 
    match ver with 
    | ProtocolVersionType.SSL_3p0 -> ssl_prf pms (append crandom srandom) 48
    | x when x = ProtocolVersionType.TLS_1p0 || x = ProtocolVersionType.TLS_1p1 ->
        prf pms "master secret" (append crandom srandom) 48
    | ProtocolVersionType.TLS_1p2 -> tls12prf pms "master secret" (append crandom srandom) 48
    | _ -> Error (HandshakeProto,Unsupported)

let expand_master_secret ver ms crandom srandom nb = 
  match ver with 
  | ProtocolVersionType.SSL_3p0 -> ssl_prf ms (append srandom crandom) nb
  | x when x = ProtocolVersionType.TLS_1p0 || x = ProtocolVersionType.TLS_1p1 ->
        prf ms "key expansion" (append srandom crandom) nb
  | ProtocolVersionType.TLS_1p2 -> tls12prf ms "key expansion" (append srandom crandom) nb
  | _ -> Error (HandshakeProto,Unsupported)

let split_key_block key_block hsize ksize ivsize = 
  let cmk = Array.sub key_block 0 hsize in
  let smk = Array.sub key_block hsize hsize in
  let cek = Array.sub key_block (2*hsize) ksize in
  let sek = Array.sub key_block (2*hsize+ksize) ksize in
  let civ = Array.sub key_block (2*hsize+2*ksize) ivsize in
  let siv = Array.sub key_block (2*hsize+2*ksize+ivsize) ivsize in
  (cmk,smk,cek,sek,civ,siv)

let generateKeys role cr sr pv cs ms =
  match securityParameters_of_ciphersuite cs with
  | Error (x,y) -> Error(x,y)
  | Correct (sp) ->
      (* RFC2246 uses the field IV_size without defining it *)
      let hsize = get_hash_size sp.mac_algorithm in
      let ksize = get_block_cipher_size sp.bulk_cipher_algorithm in
      let ivsize = 
        if pv >= ProtocolVersionType.TLS_1p1 then
            0
        else
            ksize
      let nb = 2 * (hsize + ksize + ivsize) in
      match expand_master_secret pv ms cr sr nb with
      | Error (x,y) -> Error (x,y)
      | Correct (key_block) ->
          let (cmk,smk,cek,sek,civ,siv) = split_key_block key_block hsize ksize ivsize in 
          let civ,siv = 
            if pv >= ProtocolVersionType.TLS_1p1 then
              let iv = Crypto.mkRandom ksize in
              iv,iv
            else
              civ,siv
          in
          let rmk,rek,riv,wmk,wek,wiv = 
            match role with 
              | ClientRole -> smk,sek,siv,cmk,cek,civ
              | ServerRole -> cmk,cek,civ,smk,sek,siv
          in
          correct ((sp,rmk,rek,riv,wmk,wek,wiv))

let split_varLen data lenSize =
    let (lenBytes,data) = split data lenSize in
    let len = int_of_bytes lenSize lenBytes in
    split data len

let parseSHello data =
    let (serverVerBytes,data) = split data 2 in
    let serverVer = protocolVersionType_of_bytes serverVerBytes in
    let (serverTsBytes,data) = split data 4 in
    let serverTs = int_of_bytes 4 serverTsBytes in
    let (serverRdmBytes,data) = split data 28 in
    let serverRdm = {time = serverTs; rnd = serverRdmBytes} in
    let (sid,data) = split_varLen data 1 in
    let (csBytes,data) = split data 2 in
    let cs = cipherSuite_of_bytes csBytes in
    let (cmBytes,data) = split data 1 in
    let cm = compression_of_bytes cmBytes in
    ({ server_version = serverVer
       sh_random = serverRdm
       sh_session_id = sid
       cipher_suite = cs
       compression_method = cm
       neg_extensions = data},
      append serverTsBytes serverRdmBytes)

let rec parseCertificate_int toProcess list =
    if equalBytes toProcess empty_bstr then
        correct(list)
    else
        let (nextCertBytes,toProcess) = split_varLen toProcess 3 in
        match certificate_of_bytes nextCertBytes with
        | Error(x,y) -> Error(x,y)
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
        let thisInt = int_of_bytes 1 thisByte in
        let res = [enum<ClientCertType>thisInt] @ res in
        certTypeList_of_bytes data res
    else
        let thisInt = int_of_bytes 1 data in
        [enum<ClientCertType>thisInt] @ res

let rec sigAlgsList_of_bytes data res =
    if length data > 2 then
        let (thisFieldBytes,data) = split data 2 in
        let (thisHashB,thisSigB) = split thisFieldBytes 1 in
        let thisHash = int_of_bytes 1 thisHashB in
        let thisSig = int_of_bytes 1 thisSigB in
        let thisField = {SaHA_hash = enum<HashAlg>thisHash; SaHA_signature = enum<SigAlg>thisSig} in
        let res = [thisField] @ res in
        sigAlgsList_of_bytes data res
    else
        let (thisHashB,thisSigB) = split data 1 in
        let thisHash = int_of_bytes 1 thisHashB in
        let thisSig = int_of_bytes 1 thisSigB in
        let thisField = {SaHA_hash = enum<HashAlg>thisHash; SaHA_signature = enum<SigAlg>thisSig} in
        [thisField] @ res

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
    let (sigAlgs,data) = (
        if ver = ProtocolVersionType.TLS_1p2 then
            let (sigAlgsBytes,data) = split_varLen data 2 in
            let sigAlgsList = sigAlgsList_of_bytes sigAlgsBytes [] in
            (Some(sigAlgsList),data)
        else
            (None,data)) in
    let (distNamesBytes,_) = split_varLen data 2 in
    let distNamesList = distNamesList_of_bytes distNamesBytes [] in
    { client_certificate_type = certTypeList;
      signature_and_hash_algorithm = sigAlgs;
      certificate_authorities = distNamesList}

let find_client_cert certReqMsg =
    (* TODO *) None

let prepare_output hs_state clSpecState sinfo =
    let clientCertBytes =
        match clSpecState.must_send_cert with
        | Some (_) ->
            makeCertificateBytes clSpecState.client_certificate
        | None ->
            empty_bstr

    match makeClientKEXBytes hs_state clSpecState sinfo with
    | Error (x,y) -> Error (x,y)
    | Correct (clientKEXBytes) ->
        let certificateVerifyBytesResult =
            match sinfo.clientID with
            | None ->
                (* No client certificate ==> no certificateVerify message *)
                correct (empty_bstr)
            | Some (cert) ->
                if certificate_has_signing_capability cert then
                    let to_sign = appendList [hs_state.hs_msg_log;clientCertBytes;clientKEXBytes] in
                    match clSpecState.must_send_cert with
                    | None -> unexpectedError "[prepare_output] If client sent a certificate, it must have been requested to."
                    | Some (certReqMsg) ->
                        makeCertificateVerifyBytes cert to_sign sinfo.more_info.mi_protocol_version certReqMsg
                else
                    correct (empty_bstr)
        match certificateVerifyBytesResult with
        | Error (x,y) -> Error (x,y)
        | Correct (certificateVerifyBytes) ->
            (* Enqueue current messages *)
            let to_send = appendList [clientCertBytes;clientKEXBytes;certificateVerifyBytes] in
            let new_outgoing = append hs_state.hs_outgoing to_send in
            let hs_state = {hs_state with hs_outgoing = new_outgoing} in

            (* Handle CCS and Finished, including computation of session secrets *)
            match compute_master_secret sinfo.more_info.mi_pms sinfo.more_info.mi_protocol_version hs_state.hs_client_random hs_state.hs_server_random with
            | Error (x,y) -> Error(x,y)
            | Correct(ms) ->
                correct ((hs_state,sinfo))

let init_handshake role poptions =
    let info = init_sessionInfo role in
    match role with
    | ClientRole ->
        let (cHelloBytes,client_random) = makeCHelloBytes poptions empty_bstr in
        let state = {hs_outgoing = cHelloBytes
                     ccs_outgoing = None
                     hs_outgoing_after_ccs = empty_bstr
                     hs_incoming = empty_bstr
                     hs_info = info
                     poptions = poptions
                     pstate = Client (ServerHello(None))
                     hs_msg_log = empty_bstr
                     hs_client_random = client_random
                     hs_server_random = empty_bstr} in
        (info,state)
    | ServerRole ->
        let state = {hs_outgoing = empty_bstr
                     ccs_outgoing = None
                     hs_outgoing_after_ccs = empty_bstr
                     hs_incoming = empty_bstr
                     hs_info = info
                     poptions = poptions
                     pstate = Server (ClientHello)
                     hs_msg_log = empty_bstr
                     hs_client_random = empty_bstr
                     hs_server_random = empty_bstr} in
        (info,state)

let resume_handshake role info poptions =
    let sidOp = info.sessionID in
    match sidOp with
    | None -> unexpectedError "[resume_handshake] must be invoked on a non-null session"
    | Some (sid) ->
        (* Ensure the sid is in the SessionDB *)
        match SessionDB.select poptions sid with
        | None -> unexpectedError "[resume_handshake] requested session expired or never stored in DB"
        | Some (_) ->
            match role with
            | ClientRole ->
                let (cHelloBytes,client_random) = makeCHelloBytes poptions sid in
                let state = {hs_outgoing = cHelloBytes
                             ccs_outgoing = None
                             hs_outgoing_after_ccs = empty_bstr
                             hs_incoming = empty_bstr
                             hs_info = info
                             poptions = poptions
                             pstate = Client (ServerHello(Some(info)))
                             hs_msg_log = empty_bstr
                             hs_client_random = client_random
                             hs_server_random = empty_bstr} in
                state
            | ServerRole ->
                let state = {hs_outgoing = empty_bstr
                             ccs_outgoing = None
                             hs_outgoing_after_ccs = empty_bstr
                             hs_incoming = empty_bstr
                             hs_info = info
                             poptions = poptions
                             pstate = Server (ClientHello)
                             hs_msg_log = empty_bstr
                             hs_client_random = empty_bstr
                             hs_server_random = empty_bstr} in
                state

let start_rehandshake (state:hs_state) (ops:protocolOptions) =
    (* TODO: fill some outgoing buffers, discard current session... *)
    state

let start_rekey (state:hs_state) (ops:protocolOptions) =
    (* TODO: fill some outgoing buffers, don't discard current session... *)
    state

let start_hs_request (state:hs_state) (ops:protocolOptions) =
    (* TODO: fill the ougtgoing buffer with the HelloRequest... *)
    state

let new_session_idle state new_info =
    match state.pstate with
    | Client (s) ->
        {hs_outgoing = empty_bstr;
         ccs_outgoing = None;
         hs_outgoing_after_ccs = empty_bstr;
         hs_incoming = empty_bstr;
         hs_info = new_info;
         poptions = state.poptions;
         pstate = Client(CIdle);
         hs_msg_log = empty_bstr
         hs_client_random = empty_bstr
         hs_server_random = empty_bstr}
    | Server (s) ->
        {hs_outgoing = empty_bstr;
         ccs_outgoing = None;
         hs_outgoing_after_ccs = empty_bstr;
         hs_incoming = empty_bstr;
         hs_info = new_info;
         poptions = state.poptions;
         pstate = Server(SIdle);
         hs_msg_log = empty_bstr
         hs_client_random = empty_bstr
         hs_server_random = empty_bstr}

let enqueue_fragment hs_state fragment =
    let new_inc = append hs_state.hs_incoming fragment in
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
        let len = int_of_bytes 3 lenb in
        if length rem < len then
            (* not enough payload, try next time *)
            (hs_state, None)
        else
            let hstype = hs_type_of_bytes hstypeb in
            let (payload,rem) = split rem len in
            let hs_state = { hs_state with hs_incoming = rem } in
            let to_log = appendList [hstypeb;lenb;payload] in
            (hs_state, Some(hstype,payload,to_log))
        
let rec recv_fragment_client (hs_state:hs_state) (must_change_ver:ProtocolVersionType Option) =
    let (hs_state,new_packet) = parse_fragment hs_state in
    match new_packet with
    | None ->
      match must_change_ver with
      | None -> (correct (HSAck), hs_state)
      | Some (pv) -> (correct (HSChangeVersion(ClientRole,pv)),hs_state)
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
            | ServerHello(sinfoOpt) ->
                let (shello,server_random) = parseSHello payload in
                (* Sanity checks on the received message *)
                (* FIXME: are they security-relevant here? Or only functionality-relevant? *)
                
                (* Check that the server agreed version is between maxVer and minVer. *)
                if not (shello.server_version >= hs_state.poptions.minVer && shello.server_version <= hs_state.poptions.maxVer) then
                    (Error(HSProtoVersion,CheckFailed),hs_state)
                else
                    (* Check that negotiated ciphersuite is in the allowed list. Note: if resuming a session, we still have
                    to check that this ciphersuite is the expected one! *)
                    if not (List.exists (fun x -> x = shello.cipher_suite) hs_state.poptions.ciphersuites) then
                        (Error(HandshakeProto,CheckFailed),hs_state)
                    else
                        (* Same for compression method *)
                        if not (List.exists (fun x -> x = shello.compression_method) hs_state.poptions.compressions) then
                            (Error(HandshakeProto,CheckFailed),hs_state)
                        else
                            (* RFC Sec 7.4.1.4: in this implementation, we never send extensions, if the server sent any extension
                               we MUST abot the handshake with unsupported_extension fatal alter (handled by the dispatcher) *)
                            if not (equalBytes shello.neg_extensions empty_bstr) then
                                (Error(HSExtension,CheckFailed),hs_state)
                            else
                                (* Log the received packet, and store the server random *)
                                let new_log = append hs_state.hs_msg_log to_log in
                                let hs_state = {hs_state with hs_msg_log = new_log
                                                              hs_server_random = server_random}
                                match sinfoOpt with
                                | None -> (* we did not request resumption, do a full handshake *)
                                    (* define the sinfo we're going to establish *)
                                    let sinfo = { role = ClientRole
                                                  clientID = None
                                                  serverID = None
                                                  sessionID = if equalBytes shello.sh_session_id empty_bstr then None else Some(shello.sh_session_id)
                                                  more_info = { mi_protocol_version = shello.server_version
                                                                mi_cipher_suite = shello.cipher_suite
                                                                mi_compression = shello.compression_method
                                                                mi_pms = empty_bstr
                                                              }
                                                } in
                                    (* If DH_ANON, go into the ServerKeyExchange state, else go to the Certificate state *)
                                    if isAnonCipherSuite shello.cipher_suite then
                                        let hs_state = {hs_state with pstate = Client(ServerKeyExchange(sinfo))} in
                                        recv_fragment_client hs_state (Some(shello.server_version))
                                    else
                                        let hs_state = {hs_state with pstate = Client(Certificate(sinfo))} in
                                        recv_fragment_client hs_state (Some(shello.server_version))
                                | Some(sinfo) ->
                                    match sinfo.sessionID with
                                    | None -> unexpectedError "[recv_fragment] A resumed session should never have empty SID"
                                    | Some(sid) ->
                                        if sid = shello.sh_session_id then (* use resumption *)
                                            (* Check that protocol version, ciph_suite and compression method are indeed the correct ones *)
                                            if sinfo.more_info.mi_protocol_version = shello.server_version then
                                                if sinfo.more_info.mi_cipher_suite = shello.cipher_suite then
                                                    if sinfo.more_info.mi_compression = shello.compression_method then
                                                        let clSpecState = {resumed_session = true;
                                                                           must_send_cert = None;
                                                                           client_certificate = None} in
                                                        let hs_state = { hs_state with pstate = Client(CCCS(sinfo,clSpecState))}
                                                        recv_fragment_client hs_state (Some(shello.server_version))
                                                    else (Error(HandshakeProto,CheckFailed),hs_state)
                                                else (Error(HandshakeProto,CheckFailed),hs_state)
                                            else (Error(HandshakeProto,CheckFailed),hs_state)
                                        else (* server did not agreed on resumption, do a full handshake *)
                                            (* define the sinfo we're going to establish *)
                                            let sinfo = { role = ClientRole
                                                          clientID = None
                                                          serverID = None
                                                          sessionID = if equalBytes shello.sh_session_id empty_bstr then None else Some(shello.sh_session_id)
                                                          more_info = { mi_protocol_version = shello.server_version
                                                                        mi_cipher_suite = shello.cipher_suite
                                                                        mi_compression = shello.compression_method
                                                                        mi_pms = empty_bstr
                                                                      }
                                                        } in
                                            (* If DH_ANON, go into the ServerKeyExchange state, else go to the Certificate state *)
                                            if isAnonCipherSuite shello.cipher_suite then
                                                let hs_state = {hs_state with pstate = Client(ServerKeyExchange(sinfo))} in
                                                recv_fragment_client hs_state (Some(shello.server_version))
                                            else
                                                let hs_state = {hs_state with pstate = Client(Certificate(sinfo))} in
                                                recv_fragment_client hs_state (Some(shello.server_version))
            | _ -> (* ServerHello arrived in the wrong state *) (Error (HandshakeProto,InvalidState), hs_state)
        | HT_certificate ->
            match cState with
            | Certificate(sinfo) ->
                match parseCertificate payload with
                | Error(x,y) -> (Error(x,y),hs_state)
                | Correct(certMsg) ->
                    if not (hs_state.poptions.certificateValidationPolicy certMsg.certificate_list) then
                        (Error(HSCertificate,CheckFailed),hs_state)
                    else (* We have validated server identity *)
                        (* Log the received packet *)
                        let new_log = append hs_state.hs_msg_log to_log in
                        let hs_state = {hs_state with hs_msg_log = new_log} in           
                        (* update the sinfo we're establishing *)
                        let sinfo = {sinfo with serverID = Some(certMsg.certificate_list.Head)} in
                        if cipherSuiteRequiresKeyExchange sinfo.more_info.mi_cipher_suite then
                            let hs_state = {hs_state with pstate = Client(ServerKeyExchange(sinfo))} in
                            recv_fragment_client hs_state must_change_ver
                        else
                            let hs_state = {hs_state with pstate = Client(CertReqOrSHDone(sinfo))} in
                            recv_fragment_client hs_state must_change_ver
            | _ -> (* Certificate arrived in the wrong state *) (Error (HandshakeProto,InvalidState), hs_state)
        | HT_server_key_exchange ->
            match cState with
            | ServerKeyExchange(sinfo) ->
                (* TODO *) (Error (HandshakeProto,Unsupported), hs_state)
            | _ -> (* Server Key Exchange arrived in the wrong state *) (Error (HandshakeProto,InvalidState), hs_state)
        | HT_certificate_request ->
            match cState with
            | CertReqOrSHDone(sinfo) ->
                (* Log the received packet *)
                let new_log = append hs_state.hs_msg_log to_log in
                let hs_state = {hs_state with hs_msg_log = new_log} in

                let certReqMsg = parseCertReq sinfo.more_info.mi_protocol_version payload in
                let client_cert = find_client_cert certReqMsg in
                (* Update the sinfo we're establishing *)
                (* FIXME *)
                let clSpecState = {resumed_session = false;
                                   must_send_cert = Some(certReqMsg);
                                   client_certificate = client_cert} in
                let hs_state = {hs_state with pstate = Client(CSHDone(sinfo,clSpecState))} in
                recv_fragment_client hs_state must_change_ver
            | _ -> (* Certificate Request arrived in the wrong state *) (Error (HandshakeProto,InvalidState), hs_state)
        | HT_server_hello_done ->
            match cState with
            | CertReqOrSHDone(sinfo) ->
                if not (equalBytes payload empty_bstr) then
                    (Error(HSParsing,CheckFailed),hs_state)
                else
                    (* Log the received packet *)
                    let new_log = append hs_state.hs_msg_log to_log in
                    let hs_state = {hs_state with hs_msg_log = new_log} in

                    let clSpecState = {
                        resumed_session = false;
                        must_send_cert = None;
                        client_certificate = None} in
                    match prepare_output hs_state clSpecState sinfo with
                    | Error (x,y) -> (Error (x,y), hs_state)
                    | Correct (result) ->
                        let (hs_state,sinfo) = result in
                        let hs_state = {hs_state with pstate = Client(CCCS(sinfo,clSpecState))}
                        recv_fragment_client hs_state must_change_ver
            | CSHDone(sinfo,clSpecState) ->
                if not (equalBytes payload empty_bstr) then
                    (Error(HSParsing,CheckFailed),hs_state)
                else
                    (* Log the received packet *)
                    let new_log = append hs_state.hs_msg_log to_log in
                    let hs_state = {hs_state with hs_msg_log = new_log} in

                    match prepare_output hs_state clSpecState sinfo with
                    | Error (x,y) -> (Error (x,y), hs_state)
                    | Correct (result) ->
                        let (hs_state,sinfo) = result in
                        let hs_state = {hs_state with pstate = Client(CCCS(sinfo,clSpecState))}
                        recv_fragment_client hs_state must_change_ver
            | _ -> (* Server Hello Done arrived in the wrong state *) (Error (HandshakeProto,InvalidState), hs_state)
        | _ -> (* Unsupported/Wrong message *) (Error (HandshakeProto,Unsupported), hs_state)
      
      (* Should never happen *)
      | Server(_) -> unexpectedError "[recv_fragment_client] should only be invoked when in client role."

let recv_fragment_server (hs_state:hs_state) =
    (Error(HandshakeProto,Unsupported),hs_state)

let recv_fragment (hs_state:hs_state) (fragment:fragment) =
    let hs_state = enqueue_fragment hs_state fragment in
    match hs_state.pstate with
    | Client (_) -> recv_fragment_client hs_state None
    | Server (_) -> recv_fragment_server hs_state

let recv_ccs (hs_state: hs_state) (fragment:fragment): ((ccs_data Result) * hs_state) =
    (Error (HandshakeProto,Unsupported),hs_state)