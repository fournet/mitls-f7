#light "off"
/// <summary>
/// Module receiving, sending and forwarding TLS Client Hello messages.
/// </summary>
module FlexTLS.FlexClientHello

open NLog

open Bytes
open Error
open TLSInfo
open TLSExtensions
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexState
open FlexHandshake




/// <summary>
/// Establish a desired set of values from provided FClientHello record and config
/// </summary>
/// <param name="fch"> Desired client hello </param>
/// <param name="cfg"> Desired config </param>
/// <returns> Updated FClientHello record * Updated config </returns>
let fillFClientHelloANDConfig (fch:FClientHello) (cfg:config) : FClientHello * config =
    (* pv = Is there some pv ? If no, check config maxVer *)
    // FIXME : There is a corner case when the user sets fch pv to default because it should have priority over cfg.maxVer
    let pv =
        match fch.pv = FlexConstants.nullFClientHello.pv with
        | false -> fch.pv
        | true -> cfg.maxVer
    in

    (* rand = Is there random bytes ? If no, create some *)
    let rand =
        match fch.rand = FlexConstants.nullFClientHello.rand with
        | false -> fch.rand
        | true -> Nonce.mkHelloRandom(pv)
    in

    (* sid = Is there a sid ? If no, get the default empty one *)
    let sid = fch.sid in
    
    (* suites = Is there some ? If no, check config *)
    // FIXME : There is a corner case when the user sets fch suites to default because it should have priority over cfg.ciphersuites
    let suites =
        match fch.suites = FlexConstants.nullFClientHello.suites with
        | false -> fch.suites
        | true -> (match FlexConstants.names_of_cipherSuites cfg.ciphersuites with
            | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(csl) -> csl)
    in

    (* comps = Is there some ? If no, check config *)
    // FIXME : There is a corner case when the user sets fch comps to default because it should have priority over cfg.compressions
    let comps =
        match fch.comps = FlexConstants.nullFClientHello.comps with
        | false -> fch.comps
        | true -> cfg.compressions
    in

    (* Update cfg with correct informations *)
    let cfg = { cfg with 
                maxVer = pv;
                ciphersuites = TLSConstants.cipherSuites_of_nameList suites;
                compressions = comps;
              }
    in

    (* ext = Is there some ? If no, generate using config *)
    let ext =
        match fch.ext = FlexConstants.nullFClientHello.ext with
        | false -> fch.ext
        | true -> 
            let ci = initConnection Client rand in
            prepareClientExtensions cfg ci empty_bytes
    in

    (* Update fch with correct informations and sets payload to empty bytes *)
    let fch = { pv = pv;
                rand = rand;
                sid = sid;
                suites = suites;
                comps = comps;
                ext = ext;
                payload = empty_bytes;
              } 
    in
    (fch,cfg)

/// <summary>
/// Update channel's Epoch Init Protocol version to the one chosen by the user if we are in an InitEpoch, else do nothing 
/// </summary>
/// <param name="st"> State of the current Handshake </param>
/// <param name="fch"> Client hello message containing the desired protocol version </param>
/// <returns> Updated state of the handshake </returns>
let fillStateEpochInitPvIFIsEpochInit (st:state) (fch:FClientHello) : state =
    if TLSInfo.isInitEpoch st.read.epoch then
        let st = FlexState.updateIncomingRecordEpochInitPV st fch.pv in
        let st = FlexState.updateOutgoingRecordEpochInitPV st fch.pv in
        st
    else
        st




/// <summary>
/// Module receiving, sending and forwarding TLS Client Hello messages.
/// </summary>
type FlexClientHello =
    class

    /// <summary>
    /// Receive a ClientHello message from the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <returns> Updated state * Next security context in negociation * FClientHello message record </returns>
    static member receive (st:state) : state * nextSecurityContext * FClientHello =
        LogManager.GetLogger("file").Info("# CLIENT HELLO : FlexClientHello.receive");
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_client_hello  ->    
            (match parseClientHello payload with
            | Error (ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (pv,cr,sid,clientCipherSuites,cm,cextL) -> 
                let csnames = match FlexConstants.names_of_cipherSuites clientCipherSuites with
                    | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
                    | Correct(suites) -> suites
                in
                let cextL =
                    match parseClientExtensions cextL clientCipherSuites with
                    | Error(ad,x) -> failwith x
                    | Correct(extL)-> extL
                in
                let fch = { FlexConstants.nullFClientHello with
                            pv = pv;
                            rand = cr;
                            sid = sid;
                            suites = csnames;
                            comps = cm;
                            ext = cextL;
                            payload = to_log;
                          } 
                in
                let si  = { FlexConstants.nullSessionInfo with 
                            init_crand = cr;
                          } 
                in
                let nsc = { FlexConstants.nullNextSecurityContext with
                            si = si;
                            crand = cr; 
                          } 
                in
                let st = fillStateEpochInitPvIFIsEpochInit st fch in
                LogManager.GetLogger("file").Debug(sprintf "--- Protocol Version : %A" fch.pv);
                LogManager.GetLogger("file").Debug(sprintf "--- Sid : %s" (Bytes.hexString(fch.sid)));
                LogManager.GetLogger("file").Debug(sprintf "--- Client Random : %s" (Bytes.hexString(fch.rand)));
                LogManager.GetLogger("file").Debug(sprintf "--- Ciphersuites : %A" fch.suites);
                LogManager.GetLogger("file").Debug(sprintf "--- Compressions : %A" fch.comps);
                LogManager.GetLogger("file").Debug(sprintf "--- Extensions : %A" fch.ext);
                LogManager.GetLogger("file").Info(sprintf "--- Payload : %s" (Bytes.hexString(payload)));
                (st,nsc,fch)
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "Message type should be HT_client_hello")
 
    /// <summary>
    /// Prepare ClientHello message bytes that will not be sent to the network stream
    /// </summary>
    /// <param name="cfg"> Desired config </param>
    /// <param name="crand"> Client random value </param>
    /// <param name="csid"> Client desired sid </param>
    /// <param name="cExtL"> Client list of extension </param>
    /// <returns> FClientHello message record </returns>
    static member prepare (cfg:config, crand:bytes, csid:bytes, cExtL:list<clientExtension>) : FClientHello =
        let exts = clientExtensionsBytes cExtL in
        let fch,cfg = fillFClientHelloANDConfig  FlexConstants.nullFClientHello cfg in

        let payload = HandshakeMessages.clientHelloBytes cfg crand csid exts in
        let fch = { fch with rand = crand; sid = csid; ext = cExtL; payload = payload } in
        fch


    /// <summary>
    /// Send ClientHello message to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="fch"> Desired client hello </param>
    /// <param name="cfg"> Desired config </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * Next security context in negociation * FClientHello message record </returns>
    static member send (st:state, ?fch:FClientHello, ?cfg:config, ?fp:fragmentationPolicy) : state * nextSecurityContext * FClientHello =
        let ns = st.ns in
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let fch = defaultArg fch FlexConstants.nullFClientHello in
        let cfg = defaultArg cfg defaultConfig in
        
        let fch,cfg = fillFClientHelloANDConfig fch cfg in
        let st = fillStateEpochInitPvIFIsEpochInit st fch in

        let st,fch = FlexClientHello.send(st,cfg,fch.rand,fch.sid,fch.ext,fp) in
        
        let offers = 
            match TLSExtensions.getOfferedDHGroups fch.ext with
            | None -> []
            | Some(gl) ->
                let dh13 g =
                    DH13({group = g; x = empty_bytes; gx = empty_bytes; gy = empty_bytes})
                in
                List.map dh13 gl
        in
        let si  = { FlexConstants.nullSessionInfo with init_crand = fch.rand } in
        let nsc = { FlexConstants.nullNextSecurityContext with
                    si = si;
                    crand = fch.rand; 
                    offers = offers; 
                  } 
        in
        st,nsc,fch
    
    /// <summary>
    /// Send ClientHello message to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="fch"> Desired client hello </param>
    /// <param name="cfg"> Desired config </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * Next security context in negociation * FClientHello message record </returns>
    static member send (st:state, cfg:config, crand:bytes, csid:bytes, cExtL:list<clientExtension>, ?fp:fragmentationPolicy) : state * FClientHello =
        LogManager.GetLogger("file").Info("# CLIENT HELLO : FlexClientHello.send");
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let exts = clientExtensionsBytes cExtL in

        let fch = FlexClientHello.prepare(cfg,crand,csid,cExtL) in
        let st = FlexHandshake.send(st,fch.payload,fp) in

        LogManager.GetLogger("file").Debug(sprintf "--- Protocol Version : %A" fch.pv);
        LogManager.GetLogger("file").Debug(sprintf "--- Sid : %s" (Bytes.hexString(fch.sid)));
        LogManager.GetLogger("file").Debug(sprintf "--- Client Random : %s" (Bytes.hexString(fch.rand)));
        LogManager.GetLogger("file").Debug(sprintf "--- Ciphersuites : %A" fch.suites);
        LogManager.GetLogger("file").Debug(sprintf "--- Compressions : %A" fch.comps);
        LogManager.GetLogger("file").Debug(sprintf "--- Extensions : %A" fch.ext);
        st,fch
    
    end
