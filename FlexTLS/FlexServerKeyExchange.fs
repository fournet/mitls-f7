#light "off"

module FlexServerKeyExchange

open Bytes
open Error
open TLSInfo
open TLSConstants
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexHandshake
open FlexSecrets




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

    static member receiveDHE (st:state, nsc:nextSecurityContext, ?check_sig:bool, ?minDHsize:nat*nat): state * nextSecurityContext * FServerKeyExchange =
        let check_sig = defaultArg check_sig false in
        let minDHsize = defaultArg minDHsize FlexConstants.minDHSize in
        let st,fske = FlexServerKeyExchange.receiveDHE(st,nsc.si.protocol_version,nsc.si.cipher_suite,minDHsize) in
        let nsc = {nsc with kex = fske.kex} in
        if check_sig then
            let kexDH =
                match nsc.kex with
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

    (* Receive DH ServerKeyExchange *)
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


    (* Send DHE ServerKeyExchange *)
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
        let kexdh = match nsc.kex with
            | DH(kexdh) -> kexdh
            | _ -> FlexConstants.nullKexDH
        in
        let st,fske = FlexServerKeyExchange.sendDHE(st,kexdh,nsc.crand,nsc.srand,nsc.si.protocol_version,sAlg,sKey,fp) in
        let nsc = {nsc with kex = fske.kex} in
        st,nsc,fske

    (* Send DHE ServerKeyExchange *)
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
