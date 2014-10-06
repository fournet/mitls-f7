#light "off"

module FlexServerHello

open NLog

open Bytes
open Error
open TLSInfo
open TLSConstants
open TLSExtensions
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexState
open FlexHandshake




/// <summary>
/// Inference on user provided information
/// </summary>
/// <param name="fsh"> FServerHello message record </param>
/// <param name="si"> Session information being negociated </param>
/// <returns> Updated FServerHello message record * Updated session infos </returns>
let fillFServerHelloANDSi (fsh:FServerHello) (si:SessionInfo) : FServerHello * SessionInfo =
    (* rand = Is there random bytes ? If no, create some *)
    let rand =
        match fsh.rand = FlexConstants.nullFServerHello.rand with
        | false -> fsh.rand
        | true -> Nonce.mkHelloRandom si.protocol_version
    in

    (* Update fch with correct informations and sets payload to empty bytes *)
    let fsh = { fsh with 
                rand = rand;
                payload = empty_bytes 
              } 
    in

    (* Update si with correct informations from fsh *)
    let si = { si with
               protocol_version = fsh.pv;
               sessionID = fsh.sid;
               cipher_suite = TLSConstants.cipherSuite_of_name fsh.suite;
               compression = fsh.comp;
               init_srand = fsh.rand;
             } 
    in
    (fsh,si)

/// <summary>
/// Update channel's Epoch Init Protocol version to the one chosen by the user if we are in an InitEpoch, else do nothing
/// </summary>
/// <param name="st"> State of the current Handshake </param>
/// <param name="fsh"> FServerHello message record </param>
/// <returns> Updated state </returns>
let fillStateEpochInitPvIFIsEpochInit (st:state) (fsh:FServerHello) : state =
    if TLSInfo.isInitEpoch st.read.epoch then
        let st = FlexState.updateIncomingRecordEpochInitPV st fsh.pv in
        let st = FlexState.updateOutgoingRecordEpochInitPV st fsh.pv in
        st
    else
        st




type FlexServerHello = 
    class

    /// <summary>
    /// Receive a ServerHello message from the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="fch"> FClientHello containing the client extensions </param>
    /// <param name="nsc"> Optional Next security context being negociated </param>
    /// <returns> Updated state * Updated next securtity context * FServerHello message record </returns>
    static member receive (st:state, fch:FClientHello, ?nsc:nextSecurityContext) : state * nextSecurityContext * FServerHello =
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let st,fsh,negExts = FlexServerHello.receive(st,fch.ext) in
        let si  = { nsc.si with 
                    init_srand = fsh.rand;
                    protocol_version = fsh.pv;
                    sessionID = fsh.sid;
                    cipher_suite = cipherSuite_of_name fsh.suite;
                    compression = fsh.comp;
                    extensions = negExts;
                  } 
        in
        let keys = 
            match getNegotiatedDHGroup negExts with
            | None -> nsc.keys
            | Some(group) ->
                let kex = 
                    match List.tryFind
                        (fun x -> match x with
                        | DH13(off) -> off.group = group
                        | _ -> false) nsc.offers with
                    | None -> DH13 ({group = group; x = empty_bytes; gx = empty_bytes; gy = empty_bytes})
                    | Some(kex) -> kex
                in
                {nsc.keys with kex = kex}
        in
        let nsc = { nsc with
                    si = si;
                    srand = fsh.rand;
                    keys = keys;
                  }
        in
        st,nsc,fsh
        
    
    /// <summary>
    /// Receive a ServerHello message from the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <returns> Updated state * Updated next securtity context * FServerHello message record * Negociated extensions </returns>
    static member receive (st:state, cextL:list<clientExtension>) : state * FServerHello * negotiatedExtensions =
        LogManager.GetLogger("file").Info("# SERVER HELLO : FlexServerHello.reveive");
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_server_hello  ->    
            (match parseServerHello payload with
            | Error (ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (pv,sr,sid,cs,cm,sexts) ->
                let IsResuming = (not (sid = empty_bytes)) in
                let csname = match TLSConstants.name_of_cipherSuite cs with
                    | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
                    | Correct(cs) -> cs
                in
                let sextL = 
                    match parseServerExtensions sexts with
                    | Error(ad,x) -> failwith x
                    | Correct(sextL)-> sextL
                in
                let negExts = 
                    match negotiateClientExtensions cextL sextL IsResuming cs with
                    | Error(ad,x) -> failwith x
                    | Correct(exts) -> exts
                in
                let fsh = { pv = pv;
                            rand = sr;
                            sid = sid;
                            suite = csname;
                            comp = cm;
                            ext = sextL;
                            payload = to_log; 
                          } 
                in
                let st = fillStateEpochInitPvIFIsEpochInit st fsh in
                LogManager.GetLogger("file").Debug(sprintf "--- Protocol Version : %A" fsh.pv);
                LogManager.GetLogger("file").Debug(sprintf "--- Sid : %s" (Bytes.hexString(fsh.sid)));
                LogManager.GetLogger("file").Debug(sprintf "--- Server Random : %s" (Bytes.hexString(fsh.rand)));
                LogManager.GetLogger("file").Info(sprintf "--- Ciphersuite : %A" fsh.suite);
                LogManager.GetLogger("file").Debug(sprintf "--- Compression : %A" fsh.comp);
                LogManager.GetLogger("file").Debug(sprintf "--- Extensions : %A" fsh.ext);
                LogManager.GetLogger("file").Info(sprintf "--- Payload : %s" (Bytes.hexString(payload)));
                st,fsh,negExts
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "message type should be HT_server_hello")
           
    /// <summary>
    /// Prepare a ServerHello message that will not be sent to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="si"> Session Info of the currently negociated next security context </param>
    /// <param name="cextL"> Client extensions list </param>
    /// <param name="cfg"> Optional Configuration of the server </param>
    /// <param name="verify_datas"> Optional verify data for client and server in case of renegociation </param>
    /// <returns> Updated state * Updated negociated session informations * FServerHello message record </returns>
    static member prepare (st:state, si:SessionInfo, cextL:list<clientExtension>, ?cfg:config, ?verify_datas:(cVerifyData * sVerifyData), ?sessionHash:option<sessionHash>) : state * SessionInfo * FServerHello =
        let cfg = defaultArg cfg defaultConfig in
        let sessionHash = defaultArg sessionHash None in
        let verify_datas = defaultArg verify_datas (empty_bytes,empty_bytes) in
        let sextL,negExts = negotiateServerExtensions cextL cfg si.cipher_suite verify_datas sessionHash in
        let exts = serverExtensionsBytes sextL in
        let fsh,si = fillFServerHelloANDSi FlexConstants.nullFServerHello si in
        let si = {si with extensions = negExts } in
        let st = fillStateEpochInitPvIFIsEpochInit st fsh in
        let payload = HandshakeMessages.serverHelloBytes si fsh.rand exts in
        let fsh = { fsh with 
                    ext = sextL;
                    payload = payload 
                  } 
        in
        st,si,fsh

    /// <summary>
    /// Send a ServerHello message to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="fch"> FClientHello message record containing client extensions </param>
    /// <param name="nsc"> Optional Next security context being negociated </param>
    /// <param name="fsh"> Optional FServerHello message record </param>
    /// <param name="cfg"> Optional Server configuration if differs from default </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * Updated next securtity context * FServerHello message record </returns>
    static member send (st:state, fch:FClientHello, ?nsc:nextSecurityContext, ?fsh:FServerHello, ?cfg:config, ?fp:fragmentationPolicy) : state * nextSecurityContext * FServerHello =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let fsh = defaultArg fsh FlexConstants.nullFServerHello in
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let cfg = defaultArg cfg defaultConfig in

        let fsh,si = fillFServerHelloANDSi fsh nsc.si in
        let st,si,fsh = FlexServerHello.send(st,si,fch.pv,fch.sid,fch.suites,fch.comps,fch.ext,cfg=cfg,fp=fp) in
        let nsc = { nsc with
                    si = si;
                    srand = fsh.rand;
                  }
        in
        st,nsc,fsh

    /// <summary>
    /// Send a ServerHello message to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="si"> Session Info of the currently negociated next security context </param>
    /// <param name="cextL"> Client extensions list </param>
    /// <param name="cfg"> Optional Configuration of the server </param>
    /// <param name="verify_datas"> Optional verify data for client and server in case of renegociation </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * Updated negociated session informations * FServerHello message record </returns>
    static member send (st:state, si:SessionInfo, cpv: ProtocolVersion, csid:bytes, csuites:list<cipherSuiteName>, ccomps:list<Compression>, cextL:list<clientExtension>, ?cfg:config, ?verify_datas:(cVerifyData * sVerifyData), ?sessionHash:option<sessionHash>, ?fp:fragmentationPolicy) : state * SessionInfo * FServerHello =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let cfg = defaultArg cfg defaultConfig in

        let sessionHash = defaultArg sessionHash None in
        let verify_datas = defaultArg verify_datas (empty_bytes,empty_bytes) in

        // Check that randomness has been generated
        let srand = if si.init_srand = empty_bytes then Nonce.mkHelloRandom si.protocol_version else si.init_srand in

        // The server "negotiates" its first proposal included in the client's proposal
        let negotiate cList sList =
            List.tryFind (fun s -> List.exists (fun c -> c = s) cList) sList
        in
        // Protocol version
        let nPv = minPV cpv cfg.maxVer in
        if (geqPV nPv cfg.minVer) = false then
            failwith (perror __SOURCE_FILE__ __LINE__ "Protocol version negotiation")
        else
        // Ciphersuite
        match negotiate (cipherSuites_of_nameList csuites) cfg.ciphersuites with
        | Some(nCs) ->
            // Compression
            (match negotiate ccomps cfg.compressions with
            | Some(nCm) ->
                let sid = Nonce.random 32 in
                // Extensions
                let (sExtL, nExtL) = negotiateServerExtensions cextL cfg nCs verify_datas sessionHash in
                let exts = serverExtensionsBytes sExtL in
                //BB FIXME : We have to handle resumption 
                let si = { si with 
                           client_auth      = cfg.request_client_certificate;
                           sessionID        = sid;
                           protocol_version = nPv;
                           cipher_suite     = nCs;
                           compression      = nCm;
                           extensions       = nExtL;
                           init_srand       = srand;
                         }
                in
                let st,fsh = FlexServerHello.send(st,si,sExtL,fp) in
                st,si,fsh

            | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Compression method negotiation"))
        | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Ciphersuite negotiation")

    /// <summary>
    /// Send a ServerHello message to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="si"> Session Info of the currently negociated next security context </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * FServerHello message record </returns>
    static member send (st:state, si:SessionInfo, sExtL:list<serverExtension>, ?fp:fragmentationPolicy) : state * FServerHello =
        LogManager.GetLogger("file").Info("# SERVER HELLO : FlexServerHello.send");
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in

        let ext = serverExtensionsBytes sExtL in
        let payload = HandshakeMessages.serverHelloBytes si si.init_srand ext in
        let st = FlexHandshake.send(st,payload,fp) in

        let csname = match TLSConstants.name_of_cipherSuite si.cipher_suite with
            | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(cs) -> cs
        in
        let fsh = { FlexConstants.nullFServerHello with 
                    pv = si.protocol_version;
                    rand = si.init_srand;
                    sid = si.sessionID;
                    suite = csname;
                    comp = si.compression;
                    ext = sExtL;
                    payload = payload;
                  }
        in
        LogManager.GetLogger("file").Debug(sprintf "--- Protocol Version : %A" si.protocol_version);
        LogManager.GetLogger("file").Debug(sprintf "--- Sid : %s" (Bytes.hexString(si.sessionID)));
        LogManager.GetLogger("file").Debug(sprintf "--- Server Random : %s" (Bytes.hexString(si.init_srand)));
        LogManager.GetLogger("file").Info(sprintf  "--- Ciphersuite : %A" si.cipher_suite);
        LogManager.GetLogger("file").Debug(sprintf "--- Compression : %A" si.compression);
        LogManager.GetLogger("file").Debug(sprintf "--- Extensions : %A" si.extensions);
        LogManager.GetLogger("file").Info(sprintf  "--- Payload : %s" (Bytes.hexString(payload)));

        st,fsh

    end
