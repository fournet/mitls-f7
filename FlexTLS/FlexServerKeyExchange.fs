#light "off"

module FlexServerKeyExchange

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




type FlexServerKeyExchange =
    class

    /// <summary>
    /// Receive DHE ServerKeyExchange from the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="nsc"> Next security context being negociated </param>
    /// <param name="check_sig"> Optional check on the Server certificate chain </param>
    /// <param name="minDHsize"> Optional Minimal sizes for DH parameters </param>
    /// <returns> Updated state * Updated next security context * FServerKeyExchange message record </returns>
    static member receiveDHE (st:state, nsc:nextSecurityContext, ?check_sig:bool, ?minDHsize:nat*nat): state * nextSecurityContext * FServerKeyExchange =
        let check_sig = defaultArg check_sig false in
        let minDHsize = defaultArg minDHsize FlexConstants.minDHSize in
        let st,fske = FlexServerKeyExchange.receiveDHE(st,nsc.si.protocol_version,nsc.si.cipher_suite,minDHsize) in
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
    /// <param name="pv"> Protocol version negociated </param>
    /// <param name="cs"> Ciphersuite negociated </param>
    /// <param name="minDHsize"> Optional Minimal sizes for DH parameters </param>
    /// <returns> Updated state * FServerKeyExchange message record </returns>
    static member receiveDHE (st:state, pv:ProtocolVersion, cs:cipherSuite, ?minDHsize:nat*nat) : state * FServerKeyExchange =
        let minDHsize = defaultArg minDHsize FlexConstants.minDHSize in
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_server_key_exchange  ->
            (match HandshakeMessages.parseServerKeyExchange_DHE FlexConstants.dhdb minDHsize pv cs payload with
            | Error (_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (_,dhp,gy,alg,signature) ->
                let kexdh = {pg = (dhp.dhp,dhp.dhg); x = empty_bytes; gx = empty_bytes; gy = gy} in
                let fske : FServerKeyExchange = { kex = DH(kexdh); payload = to_log; sigAlg = alg; signature = signature } in
                st,fske 
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "message type should be HT_server_key_exchange")


    /// <summary>
    /// Prepare DHE ServerKeyExchange message bytes that will not be sent to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="kexdh"> Key Exchange record containing Diffie-Hellman parameters </param>
    /// <param name="crand"> Client public randomness </param>
    /// <param name="srand"> Server public randomness </param>
    /// <param name="pv"> Protocol version negociated </param>
    /// <param name="sigAlg"> Signature algorithm allowed and usually provided by a Certificate Request </param>
    /// <param name="sigKey"> Signature secret key associated to the algorithm </param>
    /// <returns> FServerKeyExchange message bytes * Updated state * FServerKeyExchange message record </returns>
    static member prepareDHE (st:state, kexdh:kexDH, crand:bytes, srand:bytes, pv:ProtocolVersion, sigAlg:Sig.alg, sigKey:Sig.skey) : bytes * state * FServerKeyExchange =
        let kexdh = filldh kexdh in
        let p,g = kexdh.pg in
        let gx  = kexdh.gx in
        let dheB = HandshakeMessages.dheParamBytes p g gx in
        let msgb = crand @| srand @| dheB in
        let sign = Sig.sign sigAlg sigKey msgb in
        let payload = HandshakeMessages.serverKeyExchangeBytes_DHE dheB sigAlg sign pv in
        let fske = { sigAlg = sigAlg; signature = sign; kex = DH(kexdh) ; payload = payload } in
        payload,st,fske

    /// <summary>
    /// Send a DHE ServerKeyExchange message to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="nsc"> Next security context being negociated </param>
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
    /// <param name="pv"> Protocol version negociated </param>
    /// <param name="sigAlg"> Signature algorithm allowed and usually provided by a Certificate Request </param>
    /// <param name="sigKey"> Signature secret key associated to the algorithm </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * FServerKeyExchange message record </returns>
    static member sendDHE (st:state, kexdh:kexDH, crand:bytes, srand:bytes, pv:ProtocolVersion, sigAlg:Sig.alg, sigKey:Sig.skey, ?fp:fragmentationPolicy) : state * FServerKeyExchange =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let kexdh = filldh kexdh in

        let p,g = kexdh.pg in
        let gx  = kexdh.gx in
        let dheB = HandshakeMessages.dheParamBytes p g gx in
        let msgb = crand @| srand @| dheB in
        let sign = Sig.sign sigAlg sigKey msgb in

        let payload = HandshakeMessages.serverKeyExchangeBytes_DHE dheB sigAlg sign pv in
        let st = FlexHandshake.send(st,payload,fp) in
        let fske = { sigAlg = sigAlg; signature = sign; kex = DH(kexdh) ; payload = payload } in
        st,fske
    
    end




type FlexServerKeyExchangeTLS13 =
    class

    /// <summary>
    /// EXPERIMENTAL TLS 1.3 Receive DHE ServerKeyExchange from the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="nsc"> Next security context that embbed the kex to be sent </param>
    /// <returns> Updated state * FServerKeyExchange message record </returns>
    // TODO BB : Min DH size ? AP: Not needed, as we only used named groups.
    static member receive (st:state, nsc:nextSecurityContext) : state * nextSecurityContext * FServerKeyExchangeTLS13 =
        let nsckex13 = 
            match nsc.keys.kex with
            | DH13(dh13) -> dh13
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "key exchange parameters has to be DH13")
        in
        let st,fske = FlexServerKeyExchangeTLS13.receive(st,nsckex13.group) in
        let gy =
            match fske.kex with
            | DHE(_,gy) -> gy
        in
        let kex13 = { nsckex13 with gy = gy } in
        let epk = {nsc.keys with kex = DH13(kex13) } in
        let nsc = {nsc with keys = epk} in
        let nsc = FlexSecrets.fillSecrets(st,Client,nsc) in
        st,nsc,fske

    /// <summary>
    /// EXPERIMENTAL TLS 1.3 Receive DHE ServerKeyExchange from the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="group"> DH group negociated and received in ServerHello </param>
    /// <returns> Updated state * FServerKeyExchange message record </returns>
    //BB TODO : The spec is not sure that we should resend the group with the public exponent so we ignore it
    static member receive (st:state, group:dhGroup) : state * FServerKeyExchangeTLS13 =
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_server_key_exchange  ->
            (match HandshakeMessages.parseTLS13SKEDHE group payload with
            | Error (_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (kex) ->
                let fske : FServerKeyExchangeTLS13 = { kex = kex; payload = to_log } in
                st,fske 
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "message type should be HT_server_key_exchange")

    /// <summary>
    /// EXPERIMENTAL TLS 1.3 Overload : Send a DHE ServerKeyExchange message to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="nsc"> Next security context that embbed the kex to be sent </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * FServerKeyExchangeTLS13 message record </returns>
    static member send (st:state, nsc:nextSecurityContext, ?fp:fragmentationPolicy) : state * nextSecurityContext * FServerKeyExchangeTLS13 =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let kex = 
            match nsc.keys.kex with
            | DH13(kex) when not (kex.gx = empty_bytes) ->
                // User-provided kex; don't alter it
                nsc.keys.kex
            | _ ->
                // User didn't provide any useful default:
                // We sample DH paramters, and get client share from its offers
                let group =
                    match getNegotiatedDHGroup nsc.si.extensions with
                    | None -> failwith (perror __SOURCE_FILE__ __LINE__ "TLS 1.3 requires a negotiated DH group")
                    | Some(group) -> group
                in
                // pick client offer
                match List.tryFind
                    (fun x -> match x with
                        | DH13(x) -> x.group = group
                        | _ -> false ) nsc.offers with
                | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Client provided no suitable offer")
                | Some(offer) ->
                    match offer with
                    | DH13(offer) ->
                        let x,gx = CoreDH.gen_key (dhgroup_to_dhparams offer.group) in
                        DH13({offer with x = x; gx = gx})
                    | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "Unimplemented or unsupported key exchange")
        in
        
        let kex13 =
            match kex with
            | DH13(offer) ->
                DHE(offer.group,offer.gx)
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "Unimplemented or unsupported key exchange")
        in
        let st,fske = FlexServerKeyExchangeTLS13.send(st,kex13,fp) in
        let epk = {nsc.keys with kex = kex } in
        let nsc = {nsc with keys = epk} in
        let nsc = FlexSecrets.fillSecrets (st,Server,nsc) in
        st,nsc,fske

    /// <summary>
    /// EXPERIMENTAL TLS 1.3 Send a DHE ServerKeyExchange message to the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="dhgroup"> Diffie-Hellman negociated group </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * FServerKeyExchangeTLS13 message record </returns>
    static member send (st:state, kex:tls13kex, ?fp:fragmentationPolicy) : state * FServerKeyExchangeTLS13 =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        
        let payload = HandshakeMessages.tls13SKEBytes kex in

        let st = FlexHandshake.send(st,payload,fp) in
        let fske : FServerKeyExchangeTLS13 = { kex = kex ; payload = payload } in
        st,fske

    end
