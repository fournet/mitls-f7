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

    static member receiveDHxANDcheckSignature (st:state, si:SessionInfo, sigAlg:Sig.alg, ?nsc:nextSecurityContext) : state * nextSecurityContext * FServerKeyExchangeDHx =
        let nsc = defaultArg nsc nullNextSecurityContext in
        let st,nsc,fske = FlexServerKeyExchange.receiveDHx(st,si,nsc) in
        match Cert.get_chain_public_signing_key si.serverID sigAlg with
                | Error(ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__  x)
                | Correct(vkey) ->
                    let kexDH = 
                        match nsc.kex with
                        | DH(kexDH) -> kexDH
                        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "key exchange mechanism should be DHx")
                    in
                    let dheB = HandshakeMessages.dheParamBytes kexDH.p kexDH.g kexDH.gx in
                    let expected = si.init_crand @| si.init_srand @| dheB in
                    if Sig.verify sigAlg vkey expected fske.signature then
                        st,nsc,fske
                    else
                        failwith (perror __SOURCE_FILE__ __LINE__  "message signature does not match the public key")

    static member receiveDHx (st:state, si:SessionInfo, ?nsc:nextSecurityContext) : state * nextSecurityContext * FServerKeyExchangeDHx =
        let nsc = defaultArg nsc nullNextSecurityContext in
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_server_key_exchange  ->
            (match HandshakeMessages.parseServerKeyExchange_DHE si.protocol_version si.cipher_suite payload with
            | Error (ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (p,g,gx,alg,signature) ->
                let kexdh = {p = p; g = g; x = empty_bytes; gx = gx; y = empty_bytes; gy = empty_bytes} in
                let nsc = { nsc with kex = DH(kexdh) } in
                let fske : FServerKeyExchangeDHx = { kex = DH(kexdh); payload = to_log; sigAlg = alg; signature = signature } in
                st,nsc,fske 
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "message type should be HT_server_key_exchange")


    static member sendDHx (st:state, si:SessionInfo, sigAlg:Sig.alg, sigKey:Sig.skey, ?fske:FServerKeyExchangeDHx, ?nsc:nextSecurityContext, ?fp:fragmentationPolicy) : state * nextSecurityContext * FServerKeyExchangeDHx =
        let ns = st.ns in
        let fp = defaultArg fp defaultFragmentationPolicy in
        let fske = defaultArg fske nullFServerKeyExchangeDHx in
        let nsc = defaultArg nsc nullNextSecurityContext in

        let (p,g,gx,x) = DH.serverGen() in
        let dheB = HandshakeMessages.dheParamBytes p g gx in
        let msgb = si.init_crand @| si.init_srand @| dheB in
        let sign = Sig.sign sigAlg sigKey msgb in

        let payload = HandshakeMessages.serverKeyExchangeBytes_DHE dheB sigAlg sign si.protocol_version in
        let st = FlexHandshake.send(st,payload,fp) in
        let xB = FlexSecrets.adh_to_dh p g gx x in
        let kexdh = {g = g; p = p; x = xB; gx = gx; y = empty_bytes; gy = empty_bytes} in
        let nsc = { nsc with kex = DH(kexdh) } in
        let fske = { fske with kex = DH(kexdh) ; payload = payload } in
        st,nsc,fske
    
    end
