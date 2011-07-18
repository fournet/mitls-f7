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
open Crypto
open AppCommon
open Principal

type clientSpecificState =
    { resumed_session: bool
    }

type clientState =
    | ServerHello of SessionInfo Option (* client proposed session to be resumed, useful to check wether we're going to do resumption or full negotiation *)
    | Certificate of SessionInfo (* the session we're creating *)
    | ServerKeyExchange of SessionInfo (* Same as above *)
    | CertReqOrSHDone of SessionInfo (* Same as above *)
    | CSHDone of SessionInfo (* Same as above *)
    | CCCS of clientSpecificState
    | CFinished of clientSpecificState
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
}

type hs_state = pre_hs_state

type HSFragReply =
  | EmptyHSFrag
  | HSFrag of bytes
  | HSWriteSideFinished
  | HSFullyFinished_Write of SessionInfo
  | CCSFrag of bytes * ccs_data

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
        let (f,rem) = split d len in
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
                   rnd = mkRandom 28} in
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
    makeHSPacket HT_client_hello data

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
    { server_version = serverVer
      sh_random = serverRdm
      sh_session_id = sid
      cipher_suite = cs
      compression_method = cm
      neg_extensions = data}

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

let parseCertReq ver data = Error(HSParsing,Internal)

let init_handshake role poptions =
    let info = init_sessionInfo role in
    match role with
    | ClientRole ->
        let state = {hs_outgoing = makeCHelloBytes poptions empty_bstr
                     ccs_outgoing = None
                     hs_outgoing_after_ccs = empty_bstr
                     hs_incoming = empty_bstr
                     hs_info = info
                     poptions = poptions
                     pstate = Client (ServerHello(None))} in
        (info,state)
    | ServerRole ->
        let state = {hs_outgoing = empty_bstr
                     ccs_outgoing = None
                     hs_outgoing_after_ccs = empty_bstr
                     hs_incoming = empty_bstr
                     hs_info = info
                     poptions = poptions
                     pstate = Server (ClientHello)} in
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
                let state = {hs_outgoing = makeCHelloBytes poptions sid
                             ccs_outgoing = None
                             hs_outgoing_after_ccs = empty_bstr
                             hs_incoming = empty_bstr
                             hs_info = info
                             poptions = poptions
                             pstate = Client (ServerHello(Some(info)))} in
                state
            | ServerRole ->
                let state = {hs_outgoing = empty_bstr
                             ccs_outgoing = None
                             hs_outgoing_after_ccs = empty_bstr
                             hs_incoming = empty_bstr
                             hs_info = info
                             poptions = poptions
                             pstate = Server (ClientHello)} in
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
        {state with hs_outgoing = empty_bstr;
                    ccs_outgoing = None;
                    hs_outgoing_after_ccs = empty_bstr;
                    hs_incoming = empty_bstr;
                    hs_info = new_info;
                    poptions = state.poptions;
                    pstate = Client(CIdle)}
    | Server (s) ->
        {state with hs_outgoing = empty_bstr;
                    ccs_outgoing = None;
                    hs_outgoing_after_ccs = empty_bstr;
                    hs_incoming = empty_bstr;
                    hs_info = new_info;
                    poptions = state.poptions;
                    pstate = Server(SIdle)}

let parse_fragment hs_state fragment =
    (* Inefficient but simple implementation:
       every time we get a new fragment, we reparse the whole received
       packet, until a full packet is received. When a full packet is received,
       it is removed from the buffer.
       This algorithm can be easily made more efficient, but requires a more
       complex code *)
    let new_inc = append hs_state.hs_incoming fragment in
    if length new_inc < 4 then
        (* Not enough data to even start parsing *)
        let hs_state = {hs_state with hs_incoming = new_inc} in
        (hs_state, None)
    else
        let (hstypeb,rem) = split new_inc 1 in
        let (lenb,rem) = split rem 3 in
        let len = int_of_bytes 3 lenb in
        if length rem < len then
            (* not enough payload, try next time *)
            let hs_state = {hs_state with hs_incoming = new_inc} in
            (hs_state, None)
        else
            let hstype = hs_type_of_bytes hstypeb in
            let (payload,rem) = split rem len in
            let hs_state = { hs_state with hs_incoming = rem } in
            (hs_state, Some(hstype,payload))
            

let recv_fragment (hs_state:hs_state) (fragment:fragment) =
    let (hs_state,new_packet) = parse_fragment hs_state fragment in
    match new_packet with
    | None -> (correct (HSAck), hs_state)
    | Some (data) ->
    let (hstype,payload) = data in
    match hs_state.pstate with

    (* *** CLIENT SIDE *** *)

    | Client (cState) ->
        match hstype with
        | HT_hello_request ->
            match cState with
            | CIdle -> (* This is a legitimate hello request. Properly handle it *)
                match hs_state.poptions.honourHelloReq with
                | HRPIgnore -> (correct (HSAck), hs_state)
                | HRPResume -> let hs_state = start_rekey hs_state hs_state.poptions in (correct (HSAck), hs_state)
                | HRPFull -> let hs_state = start_rehandshake hs_state hs_state.poptions in (correct (HSAck), hs_state)
            | _ -> (* RFC 7.4.1.1: ignore this message *) (correct (HSAck), hs_state)
        | HT_server_hello ->
            match cState with
            | ServerHello(sinfoOpt) ->
                let shello = parseSHello payload in
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
                                        (correct (HSAck),hs_state)
                                    else
                                        let hs_state = {hs_state with pstate = Client(Certificate(sinfo))} in
                                        (correct (HSAck),hs_state)
                                | Some(sinfo) ->
                                    match sinfo.sessionID with
                                    | None -> unexpectedError "[recv_fragment] A resumed session should never have empty SID"
                                    | Some(sid) ->
                                        if sid = shello.sh_session_id then (* use resumption *)
                                            (* Check that protocol version, ciph_suite and compression method are indeed the correct ones *)
                                            if sinfo.more_info.mi_protocol_version = shello.server_version then
                                                if sinfo.more_info.mi_cipher_suite = shello.cipher_suite then
                                                    if sinfo.more_info.mi_compression = shello.compression_method then
                                                        let clSpecState = {resumed_session = true} in
                                                        let hs_state = { hs_state with pstate = Client(CCCS(clSpecState))}
                                                        (correct (HSAck), hs_state)
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
                                                (correct (HSAck),hs_state)
                                            else
                                                let hs_state = {hs_state with pstate = Client(Certificate(sinfo))} in
                                                (correct (HSAck),hs_state)
            | _ -> (* ServerHello arrived in the wrong state *) (Error (HandshakeProto,InvalidState), hs_state)
        | HT_certificate ->
            match cState with
            | Certificate(sinfo) ->
                match parseCertificate payload with
                | Error(x,y) -> (Error(x,y),hs_state)
                | Correct(certMsg) ->
                    if not (hs_state.poptions.certificateValidationPolicy certMsg.certificate_list) then
                        (Error(HSCertificate,CheckFailed),hs_state)
                    else (* We have validated server identity, update the sinfo we're establishing *)
                        let sinfo = {sinfo with serverID = Some(certMsg.certificate_list.Head)} in
                        if cipherSuiteRequiresKeyExchange sinfo.more_info.mi_cipher_suite then
                            let hs_state = {hs_state with pstate = Client(ServerKeyExchange(sinfo))} in
                            (correct(HSAck),hs_state)
                        else
                            let hs_state = {hs_state with pstate = Client(CertReqOrSHDone(sinfo))} in
                            (correct(HSAck),hs_state)
            | _ -> (* Certificate arrived in the wrong state *) (Error (HandshakeProto,InvalidState), hs_state)
        | HT_server_key_exchange ->
            match cState with
            | ServerKeyExchange(sinfo) ->
                (* TODO *) (Error (HandshakeProto,Unsupported), hs_state)
            | _ -> (* Server Key Exchange arrived in the wrong state *) (Error (HandshakeProto,InvalidState), hs_state)
        | HT_certificate_request ->
            match cState with
            | CertReqOrSHDone(sinfo) ->
                match parseCertReq sinfo.more_info.mi_protocol_version payload with
                | Error(x,y) -> (Error(x,y),hs_state)
                | Correct(certReqMsg) ->
                    (* TODO *) (Error (HandshakeProto,Unsupported), hs_state)
            | _ -> (* Certificate Request arrived in the wrong state *) (Error (HandshakeProto,InvalidState), hs_state)
        | HT_server_hello_done ->
            match cState with
            | CertReqOrSHDone(sinfo) -> (* TODO *) (Error (HandshakeProto,Unsupported), hs_state)
            | CSHDone(sinfo) -> (* TODO *) (Error (HandshakeProto,Unsupported), hs_state)
            | _ -> (* Server Hello Done arrived in the wrong state *) (Error (HandshakeProto,InvalidState), hs_state)
        | _ -> (* Unsupported/Wrong message *) (Error (HandshakeProto,Unsupported), hs_state)
    
    (* *** SERVER SIDE *** *)
    
    | Server (sState) -> (Error (HandshakeProto,Unsupported),hs_state)

let recv_ccs (hs_state: hs_state) (fragment:fragment): ((ccs_data Result) * hs_state) =
    (Error (HandshakeProto,Unsupported),hs_state)