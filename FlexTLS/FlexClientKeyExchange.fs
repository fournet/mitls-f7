#light "off"

module FlexClientKeyExchange

open Bytes
open Error
open TLSConstants
open TLSInfo
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexHandshake
open FlexSecrets




let defaultKey osk certl =
    match osk with
    | Some(sk) -> sk
    | None ->
        let hint = 
            match Cert.get_hint certl with
            | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Please provide a certificate")
            | Some(ch) -> ch
        in
        match Cert.for_key_encryption FlexConstants.sigAlgs_RSA hint with
        | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Please provide a certificate for which the private key is available")
        | Some(c,sk) -> sk




type FlexClientKeyExchange =
    class

    (* Receive ClientKeyExchange for RSA ciphersuites and takes pv from FClientHello *)
    static member receiveRSA (st:state, nsc:nextSecurityContext, fch:FClientHello, ?checkPV:bool, ?sk:RSAKey.sk) : state * nextSecurityContext * FClientKeyExchange =
        let checkPV = defaultArg checkPV true in
        let sk = defaultKey sk nsc.si.serverID in
        FlexClientKeyExchange.receiveRSA(st,nsc,fch.pv,checkPV,sk)

    (* Receive ClientKeyExchange for RSA ciphersuites taking a protocol version *)
    static member receiveRSA (st:state, nsc:nextSecurityContext, pv:ProtocolVersion, ?checkPV:bool, ?sk:RSAKey.sk) : state * nextSecurityContext * FClientKeyExchange =
        let checkPV = defaultArg checkPV true in
        let sk = defaultKey sk nsc.si.serverID in
        let st,fcke = FlexClientKeyExchange.receiveRSA(st,nsc.si.serverID,pv,checkPV,sk) in
        let nsc = {nsc with kex = fcke.kex} in
        let nsc = FlexSecrets.fillSecrets(st,Server,nsc) in
        st,nsc,fcke

    (* Receive ClientKeyExchange for RSA ciphersuites taking Certificate list and a protocol version *)
    static member receiveRSA (st:state, certl:list<Cert.cert>, pv:ProtocolVersion, ?checkPV:bool, ?sk:RSAKey.sk): state * FClientKeyExchange =
        let checkPV = defaultArg checkPV true in
        let sk = defaultKey sk certl in
        let pk = 
            match Cert.get_public_encryption_key certl.Head with
            | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(pk) -> pk
        in
        let si = {FlexConstants.nullSessionInfo with serverID = certl; protocol_version = pv} in
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_client_key_exchange  ->
            (match parseClientKeyExchange_RSA si payload with
            | Error (_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (encPMS) ->
                    let pmsa = RSA.decrypt sk si si.protocol_version checkPV encPMS in
                    let pmsb = PMS.leakRSA pk si.protocol_version pmsa in
                    let kex = RSA(pmsb) in
                    let fcke : FClientKeyExchange = {kex = kex; payload = to_log } in
                    st,fcke
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "message type should be HT_client_key_exchange")
      

    (* Prepare ClientKeyExchange message bytes for RSA ciphersuites *)
    static member prepareRSA (st:state, nsc:nextSecurityContext, fch:FClientHello): bytes * state * nextSecurityContext * FClientKeyExchange =
        FlexClientKeyExchange.prepareRSA(st,nsc,fch.pv)

    (* Prepare ClientKeyExchange message bytes for RSA ciphersuites *)
    static member prepareRSA (st:state, nsc:nextSecurityContext, pv:ProtocolVersion): bytes * state * nextSecurityContext * FClientKeyExchange =
        let payload,st,fcke =
            match nsc.kex with
            | RSA(pms) ->
                if pms = empty_bytes then
                    FlexClientKeyExchange.prepareRSA(st,nsc.si.serverID,pv)
                else
                    FlexClientKeyExchange.prepareRSA(st,nsc.si.serverID,pv,pms)
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "RSA kex expected")
        in
        let nsc = {nsc with kex = fcke.kex} in
        let nsc = FlexSecrets.fillSecrets(st,Client,nsc) in
        payload,st,nsc,fcke

    (* Prepare ClientKeyExchange message bytes for RSA ciphersuites *)
    static member prepareRSA (st:state, certl:list<Cert.cert>, pv:ProtocolVersion, ?pms:bytes) : bytes * state * FClientKeyExchange =
        if certl.IsEmpty then
            failwith (perror __SOURCE_FILE__ __LINE__  "Server certificate should always be present with a RSA signing cipher suite.")
        else
            match Cert.get_chain_public_encryption_key certl with
            | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(pk) ->
                let si = {FlexConstants.nullSessionInfo with
                            protocol_version = pv;
                            serverID = certl} in
                let pms,pmsb =
                    match pms with
                    | Some(pmsb) -> (PMS.coerceRSA pk pv pmsb),pmsb
                    | None ->
                        let pms = (PMS.genRSA pk pv) in
                        pms,PMS.leakRSA pk pv pms
                in
                let encpms = RSA.encrypt pk pv pms in
                let payload = clientKeyExchangeBytes_RSA si encpms in
                let kex = RSA(pmsb) in
                let fcke : FClientKeyExchange = {kex = kex; payload = payload } in
                payload,st,fcke

    (* Send ClientKeyExchange for RSA ciphersuites, compute the PMS, MS, KEYS and update the nextSecurityContext with the FClientHello message *)
    static member sendRSA (st:state, nsc:nextSecurityContext, fch:FClientHello, ?fp:fragmentationPolicy): state * nextSecurityContext * FClientKeyExchange =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        FlexClientKeyExchange.sendRSA(st,nsc,fch.pv,fp)

    (* Send ClientKeyExchange for RSA ciphersuites, compute the PMS, MS, KEYS and update the nextSecurityContext with the protocol version *)
    static member sendRSA (st:state, nsc:nextSecurityContext, pv:ProtocolVersion, ?fp:fragmentationPolicy): state * nextSecurityContext * FClientKeyExchange =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let st,fcke =
            match nsc.kex with
            | RSA(pms) ->
                if pms = empty_bytes then
                    FlexClientKeyExchange.sendRSA(st,nsc.si.serverID,pv,fp=fp)
                else
                    FlexClientKeyExchange.sendRSA(st,nsc.si.serverID,pv,pms,fp)
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "RSA kex expected")
        in
        let nsc = {nsc with kex = fcke.kex} in
        let nsc = FlexSecrets.fillSecrets(st,Client,nsc) in
        st,nsc,fcke

    (* Send ClientKeyExchange for RSA ciphersuites *)
    static member sendRSA (st:state, certl:list<Cert.cert>, pv:ProtocolVersion, ?pms:bytes, ?fp:fragmentationPolicy) : state * FClientKeyExchange =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        if certl.IsEmpty then
            failwith (perror __SOURCE_FILE__ __LINE__  "Server certificate should always be present with a RSA signing cipher suite.")
        else
            match Cert.get_chain_public_encryption_key certl with
            | Error(_,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(pk) ->
                let si = {FlexConstants.nullSessionInfo with
                            protocol_version = pv;
                            serverID = certl} in
                let pms,pmsb =
                    match pms with
                    | Some(pmsb) -> (PMS.coerceRSA pk pv pmsb),pmsb
                    | None ->
                        let pms = (PMS.genRSA pk pv) in
                        pms,PMS.leakRSA pk pv pms
                in
                let encpms = RSA.encrypt pk pv pms in
                let payload = clientKeyExchangeBytes_RSA si encpms in
                let st = FlexHandshake.send(st,payload,fp) in
                let kex = RSA(pmsb) in
                let fcke : FClientKeyExchange = {kex = kex; payload = payload } in
                st,fcke


    (*----------------------------------------------------------------------------------------------------------------------------------------------*)
    
    // BB : Not sure about this ! Should we override the next security context with a FServerKeyExchangeDH
    (* Receive ClientKeyExchange for DHE ciphersuites, compute the PMS, MS, KEYS and update the nextSecurityContext with the FServerKeyExchangeDHx  message *)
    static member receiveDHE (st:state, fske:FServerKeyExchange, ?nsc:nextSecurityContext) : state * nextSecurityContext * FClientKeyExchange =
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let nsc = {nsc with kex = fske.kex} in
        FlexClientKeyExchange.receiveDHE(st,nsc)

    (* Receive ClientKeyExchange for DHE ciphersuites, compute the PMS, MS, KEYS and update the nextSecurityContext with a user provided kexDH record *)
    static member receiveDHE (st:state, nsc:nextSecurityContext) : state * nextSecurityContext * FClientKeyExchange =
        let kexdh =
            match nsc.kex with
            | DH(kexdh) -> kexdh
            | _         -> failwith (perror __SOURCE_FILE__ __LINE__  "key exchange mechanism should be DHE")
        in
        let st,fcke = FlexClientKeyExchange.receiveDHE(st,kexdh) in
        let nsc = {nsc with kex = fcke.kex} in
        let nsc = FlexSecrets.fillSecrets(st,Server,nsc) in
        st,nsc,fcke

    (* Receive ClientKeyExchange for DHE ciphersuites *)
    static member receiveDHE (st:state, kexdh:kexDH) : state * FClientKeyExchange =
        let (p,g),gx = kexdh.pg,kexdh.gx in
        let dhp = {FlexConstants.nullDHParams with dhp = p; dhg = g} in
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_client_key_exchange  ->
            (match HandshakeMessages.parseClientKEXExplicit_DH dhp payload with
            | Error(ad,err) -> failwith err
            | Correct(gy) ->
                let kexdh = { kexdh with gy = gy } in
                let fcke = { kex = DH(kexdh); payload = to_log } in
                st,fcke
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "message type should be HT_client_key_exchange")
        

    (* Prepare ClientKeyExchange message bytes for DHE ciphersuites *)
    static member prepareDHE (st:state, kexdh:kexDH) : bytes * state * FClientKeyExchange =        
        let p,g = kexdh.pg in
        let dhp = { FlexConstants.nullDHParams with dhp = p; dhg = g } in
        let x,gx = CoreDH.gen_key_pg p g in
        let payload = clientKEXExplicitBytes_DH gx in
        let kexdh = { kexdh with x = x; gx = gx } in
        let fcke = { kex = DH(kexdh); payload = payload } in
        payload,st,fcke

    // BB : Not sure about this ! Should we override the next security context with a FServerKeyExchangeDH
    (* Send ClientKeyExchange for DHE ciphersuites, compute the PMS, MS, KEYS and update the nextSecurityContext from a FServerKeyExchange message *)
    static member sendDHE (st:state, fske:FServerKeyExchange, ?nsc:nextSecurityContext, ?fp:fragmentationPolicy) : state * nextSecurityContext * FClientKeyExchange =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let nsc = {nsc with kex = fske.kex} in
        FlexClientKeyExchange.sendDHE(st,nsc,fp)

    (* Send ClientKeyExchange for DHE ciphersuites, compute the PMS, MS, KEYS and update the nextSecurityContext from a KEX record *)
    static member sendDHE (st:state, nsc:nextSecurityContext, ?fp:fragmentationPolicy) : state * nextSecurityContext * FClientKeyExchange =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let kexdh =
            match nsc.kex with
            | DH(kexdh) -> kexdh
            | _         -> failwith (perror __SOURCE_FILE__ __LINE__  "key exchange mechanism should be DHE")
        in
        let st,fcke = FlexClientKeyExchange.sendDHE(st,kexdh,fp) in
        let nsc = { nsc with kex = fcke.kex } in
        let nsc = FlexSecrets.fillSecrets(st,Client,nsc) in
        st,nsc,fcke

    (* Send ClientKeyExchange for DHE ciphersuites *)
    static member sendDHE (st:state, kexdh:kexDH, ?fp:fragmentationPolicy) : state * FClientKeyExchange =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        
        let p,g = kexdh.pg in
        let dhp = { FlexConstants.nullDHParams with dhp = p; dhg = g } in
        let x,gx = CoreDH.gen_key_pg p g in

        let payload = clientKEXExplicitBytes_DH gx in
        let st = FlexHandshake.send(st,payload,fp) in
        let kexdh = { kexdh with x = x; gx = gx } in
        let fcke = { kex = DH(kexdh); payload = payload } in
        st,fcke

    end
