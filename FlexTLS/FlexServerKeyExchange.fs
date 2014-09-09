#light "off"

module FlexServerKeyExchange

open Bytes
open Error
open TLSInfo
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexHandshake
open FlexSecrets




type FlexServerKeyExchange =
    class

    (* Receive DH ServerKeyExchange and check signature *)
    static member receiveDHxANDcheckSignature (st:state, si:SessionInfo, sigAlg:Sig.alg, ?nsc:nextSecurityContext) : state * nextSecurityContext * FServerKeyExchange =
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let st,nsc,fske = FlexServerKeyExchange.receiveDHx(st,si,nsc) in
        match Cert.get_chain_public_signing_key si.serverID sigAlg with
                | Error(ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__  x)
                | Correct(vkey) ->
                    let kexDH = 
                        match nsc.kex with
                        | DH(kexDH) -> kexDH
                        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "key exchange mechanism should be DHx")
                    in
                    let g,p = kexDH.gp in
                    let gx = kexDH.gx in 
                    let dheB = HandshakeMessages.dheParamBytes p g gx in
                    let expected = si.init_crand @| si.init_srand @| dheB in
                    if Sig.verify sigAlg vkey expected fske.signature then
                        st,nsc,fske
                    else
                        failwith (perror __SOURCE_FILE__ __LINE__  "message signature does not match the public key")

    (* Receive DH ServerKeyExchange *)
    static member receiveDHx (st:state, si:SessionInfo, ?nsc:nextSecurityContext) : state * nextSecurityContext * FServerKeyExchange =
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_server_key_exchange  ->
            (match HandshakeMessages.parseServerKeyExchange_DHE si.protocol_version si.cipher_suite payload with
            | Error (ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (p,g,gy,alg,signature) ->
                let kexdh = {gp = (g,p); x = empty_bytes; gx = empty_bytes; gy = gy} in
                let nsc = { nsc with kex = DH(kexdh) } in
                let fske : FServerKeyExchange = { kex = DH(kexdh); payload = to_log; sigAlg = alg; signature = signature } in
                st,nsc,fske 
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "message type should be HT_server_key_exchange")


    (* Send DH ServerKeyExchange overloaded with nextSecurityContext instead of kexdh *)
    (* Not sure this one is interesting ... *)
    static member sendDHx (st:state, si:SessionInfo, sigAlg:Sig.alg, sigKey:Sig.skey, ?nsc:nextSecurityContext, ?fp:fragmentationPolicy) : state * nextSecurityContext * FServerKeyExchange =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let kexdh = 
            match nsc.kex with 
            | DH(kexdh) -> kexdh
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "key exchange mechanism should be DHx")
        in
        FlexServerKeyExchange.sendDHx(st, si, sigAlg, sigKey, kexdh, fp)

    (* Send DH ServerKeyExchange *)
    static member sendDHx (st:state, si:SessionInfo, sigAlg:Sig.alg, sigKey:Sig.skey, ?kexdh:kexDH, ?fp:fragmentationPolicy) : state * nextSecurityContext * FServerKeyExchange =
        let (p,g,gx,x) = DH.serverGen() in
        let xB = FlexSecrets.adh_to_dh p g gx x in
        let defkexdh = {gp = (g,p); x = empty_bytes; gy = empty_bytes; gx = gx} in

        let kexdh = defaultArg kexdh defkexdh in

        let ns = st.ns in
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in

        let g,p = kexdh.gp in
        let x,gx = kexdh.x, kexdh.gx in
        let dheB = HandshakeMessages.dheParamBytes p g gx in
        let msgb = si.init_crand @| si.init_srand @| dheB in
        let sign = Sig.sign sigAlg sigKey msgb in

        let payload = HandshakeMessages.serverKeyExchangeBytes_DHE dheB sigAlg sign si.protocol_version in
        let st = FlexHandshake.send(st,payload,fp) in
        let nsc = { FlexConstants.nullNextSecurityContext with kex = DH(kexdh) } in
        let fske = { FlexConstants.nullFServerKeyExchangeDHx with sigAlg = sigAlg; signature = sign; kex = DH(kexdh) ; payload = payload } in
        st,nsc,fske
    
    end
