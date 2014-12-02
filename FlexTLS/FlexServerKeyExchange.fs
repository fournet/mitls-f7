#light "off"
/// <summary>
/// Module receiving, sending and forwarding TLS Server Key Exchange messages.
/// </summary>
module FlexTLS.FlexServerKeyExchange

open NLog

open Bytes
open Error
open TLSInfo
open TLSConstants
open TLSExtensions
open HandshakeMessages

open FlexTypes
open FlexSecrets
open FlexConstants
open FlexHandshake




/// <summary>
/// Fill kexDH structure by eventually finishing computation of all Diffie Hellman parameters.
/// </summary>
let filldh kexdh =
    let (p,g) = kexdh.pg in
    let x, gx =
        match kexdh.x,kexdh.gx with
        | x, gx when x = empty_bytes && gx = empty_bytes ->
            CoreDH.gen_key_pg p g
        | x, gx when gx = empty_bytes ->
            x, CoreDH.agreement p x g
        | x, gx -> x,gx
    in
    {kexdh with x = x; gx = gx}




/// <summary>
/// Module receiving, sending and forwarding TLS Server Key Exchange messages.
/// </summary>
type FlexServerKeyExchange =
    class

    /// <summary>
    /// Receive DHE ServerKeyExchange from the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="nsc"> Next security context being negotiated </param>
    /// <param name="check_sig"> Optional check on the Server certificate chain </param>
    /// <param name="minDHsize"> Optional Minimal sizes for DH parameters.
    ///    If provided, received DH parameters will be checked for validity and their size;
    ///    if not provided, no check at all will be performed on the received parameters </param>
    /// <returns> Updated state * Updated next security context * FServerKeyExchange message record </returns>
    static member receiveDHE (st:state, nsc:nextSecurityContext, ?check_sig:bool, ?minDHsize:nat*nat): state * nextSecurityContext * FServerKeyExchange =
        let check_sig = defaultArg check_sig false in
        let st,fske =
            match minDHsize with
            | None -> FlexServerKeyExchange.receiveDHE(st,nsc.si.protocol_version,nsc.si.cipher_suite)
            | Some(minDHsize) -> FlexServerKeyExchange.receiveDHE(st,nsc.si.protocol_version,nsc.si.cipher_suite,minDHsize)
        in
        let epk = {nsc.keys with kex = fske.kex} in
        let nsc = {nsc with keys = epk} in
        if check_sig then
            let kexDH =
                match nsc.keys.kex with
                | DH(x) -> x
                | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "Internal error: receiveDHE should return a DH kex")
            in
            let p,g = kexDH.pg in
            let gy = kexDH.gy in
            let dheB = HandshakeMessages.dheParamBytes p g gy in
            let expected = nsc.crand @| nsc.srand @| dheB in
            match Cert.get_chain_public_signing_key nsc.si.serverID fske.sigAlg with
            | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__  x)
            | Correct(vkey) ->
                if Sig.verify fske.sigAlg vkey expected fske.signature then
                    st,nsc,fske
                else
                    failwith (perror __SOURCE_FILE__ __LINE__ "Signature check failed")
        else
            st,nsc,fske

    /// <summary>
    /// Receive DHE ServerKeyExchange from the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="pv"> Protocol version negotiated </param>
    /// <param name="cs"> Ciphersuite negotiated </param>
    /// <param name="minDHsize"> Optional Minimal sizes for DH parameters.
    ///    If provided, received DH parameters will be checked for validity and their size;
    ///    if not provided, no check at all will be performed on the received parameters </param>
    /// <returns> Updated state * FServerKeyExchange message record </returns>
    static member receiveDHE (st:state, pv:ProtocolVersion, cs:cipherSuite, ?minDHsize:nat*nat) : state * FServerKeyExchange =
        LogManager.GetLogger("file").Info("# SERVER KEY EXCHANGE : FlexServerKeyExchange.receiveDHE");
        let st,hstype,payload,to_log = FlexHandshake.receive(st) in
        match hstype with
        | HT_server_key_exchange  ->
            (match HandshakeMessages.parseServerKeyExchange_DHE pv cs payload with
            | Error (_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (p,g,gy,alg,signature) ->
                LogManager.GetLogger("file").Debug(sprintf "---S Public Prime : %s" (Bytes.hexString(p)));
                LogManager.GetLogger("file").Debug(sprintf "---S Public Generator : %s" (Bytes.hexString(g)));
                LogManager.GetLogger("file").Debug(sprintf "---S Public Exponent : %s" (Bytes.hexString(gy)));
                LogManager.GetLogger("file").Debug(sprintf "---S Signature algorithm : %A" (alg));
                LogManager.GetLogger("file").Debug(sprintf "---S Signature : %s" (Bytes.hexString(signature)));
                LogManager.GetLogger("file").Info(sprintf "--- Payload : %s" (Bytes.hexString(payload)));
                (match minDHsize with
                | None -> ()
                | Some(minDHsize) ->
                    // Check params and validate y
                    match DHGroup.checkParams FlexConstants.dhdb minDHsize p g with
                    | Error (_,x) -> failwith x
                    | Correct(res) ->
                        let (_,dhp) = res in
                        match DHGroup.checkElement dhp gy with
                        | None ->
                            failwith "Server sent an invalid DH key"
                        | Some(_) -> ()
                );
                let kexdh = {pg = (p,g); x = empty_bytes; gx = empty_bytes; gy = gy} in
                let fske : FServerKeyExchange = { kex = DH(kexdh); payload = to_log; sigAlg = alg; signature = signature } in
                st,fske 
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ (sprintf "Unexpected handshake type: %A" hstype))


    /// <summary>
    /// Prepare DHE ServerKeyExchange message bytes that will not be sent to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="kexdh"> Key Exchange record containing Diffie-Hellman parameters </param>
    /// <param name="crand"> Client public randomness </param>
    /// <param name="srand"> Server public randomness </param>
    /// <param name="pv"> Protocol version negotiated </param>
    /// <param name="sigAlg"> Signature algorithm allowed and usually provided by a Certificate Request </param>
    /// <param name="sigKey"> Signature secret key associated to the algorithm </param>
    /// <returns> FServerKeyExchange message bytes * Updated state * FServerKeyExchange message record </returns>
    static member prepareDHE (kexdh:kexDH, crand:bytes, srand:bytes, pv:ProtocolVersion, sigAlg:Sig.alg, sigKey:Sig.skey) : FServerKeyExchange * kexDH =
        
        let kexdh = filldh kexdh in
        let p,g = kexdh.pg in
        let gx  = kexdh.gx in
        let dheB = HandshakeMessages.dheParamBytes p g gx in
        let msgb = crand @| srand @| dheB in
        let sign = Sig.sign sigAlg sigKey msgb in

        let payload = HandshakeMessages.serverKeyExchangeBytes_DHE dheB sigAlg sign pv in
        let fske = { sigAlg = sigAlg; signature = sign; kex = DH(kexdh) ; payload = payload } in
        // We redundantly return kexdh for a better log
        fske,kexdh

    /// <summary>
    /// Send a DHE ServerKeyExchange message to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="nsc"> Next security context being negotiated </param>
    /// <param name="sigAlgAndKey"> Optional pair of Signature Algorithm and Signing key to use by force </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * FServerKeyExchange message record </returns>
    static member sendDHE (st:state, nsc:nextSecurityContext, ?sigAlgAndKey:(Sig.alg * Sig.skey), ?fp:fragmentationPolicy) : state * nextSecurityContext * FServerKeyExchange =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let sAlg,sKey =
            match sigAlgAndKey with
            | Some(sak) -> sak
            | None ->
                match Cert.get_hint nsc.si.serverID with
                | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Wrong server certificate provided")
                | Some(hint) ->
                    let sigAlgs = TLSExtensions.default_sigHashAlg nsc.si.protocol_version nsc.si.cipher_suite in
                    match Cert.for_signing sigAlgs hint sigAlgs with
                    | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Cannot find private key for certificate")
                    | Some(_,sAlg,sKey) -> sAlg,sKey
        in
        let kexdh = match nsc.keys.kex with
            | DH(kexdh) -> kexdh
            | _ -> FlexConstants.nullKexDH
        in
        let st,fske = FlexServerKeyExchange.sendDHE(st,kexdh,nsc.crand,nsc.srand,nsc.si.protocol_version,sAlg,sKey,fp) in
        let epk = {nsc.keys with kex = fske.kex } in
        let nsc = {nsc with keys = epk} in
        st,nsc,fske

    /// <summary>
    /// Send a DHE ServerKeyExchange message to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="kexdh"> Key Exchange record containing Diffie-Hellman parameters </param>
    /// <param name="crand"> Client public randomness </param>
    /// <param name="srand"> Server public randomness </param>
    /// <param name="pv"> Protocol version negotiated </param>
    /// <param name="sigAlg"> Signature algorithm allowed and usually provided by a Certificate Request </param>
    /// <param name="sigKey"> Signature secret key associated to the algorithm </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * FServerKeyExchange message record </returns>
    static member sendDHE (st:state, kexdh:kexDH, crand:bytes, srand:bytes, pv:ProtocolVersion, sigAlg:Sig.alg, sigKey:Sig.skey, ?fp:fragmentationPolicy) : state * FServerKeyExchange =
        LogManager.GetLogger("file").Info("# SERVER KEY EXCHANGE : FlexServerKeyExchange.sendDHE");
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in

        let fske,dh = FlexServerKeyExchange.prepareDHE(kexdh,crand,srand,pv,sigAlg,sigKey) in
        let st = FlexHandshake.send(st,fske.payload,fp) in

        let p,g = dh.pg in
        LogManager.GetLogger("file").Debug(sprintf "--- Public Prime : %s" (Bytes.hexString(p)));
        LogManager.GetLogger("file").Debug(sprintf "--- Public Generator : %s" (Bytes.hexString(g)));
        LogManager.GetLogger("file").Debug(sprintf "--- Public Exponent : %s" (Bytes.hexString(dh.gx)));
        st,fske
    
    end
