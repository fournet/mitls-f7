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
        match Cert.for_key_encryption FlexConstants.calgs_RSA hint with
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
        let nsc = FlexSecrets.fillSecrets(st,Server,nsc,fcke.kex) in
        st,nsc,fcke

    (* Receive ClientKeyExchange for RSA ciphersuites taking Certificate list and a protocol version *)
    static member receiveRSA (st:state, certl:list<Cert.cert>, pv:ProtocolVersion, ?checkPV:bool, ?sk:RSAKey.sk): state * FClientKeyExchange =
        let checkPV = defaultArg checkPV true in
        let sk = defaultKey sk certl in
        let pk = 
            match Cert.get_public_encryption_key certl.Head with
            | Error(ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(pk) -> pk
        in
        let si = {FlexConstants.nullSessionInfo with serverID = certl; protocol_version = pv} in
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_client_key_exchange  ->
            (match parseClientKeyExchange_RSA si payload with
            | Error (ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (encPMS) ->
                    let pmsa = RSA.decrypt sk si si.protocol_version checkPV encPMS in
                    let pmsb = PMS.leakRSA pk si.protocol_version pmsa in
                    let kex = RSA(pmsb) in
                    let fcke : FClientKeyExchange = {kex = kex; payload = to_log } in
                    st,fcke
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "message type should be HT_client_key_exchange")
       
    (* Send ClientKeyExchange for RSA ciphersuites, compute the PMS, MS, KEYS and update the nextSecurityContext with the FClientHello message *)
    static member sendRSA (st:state, nsc:nextSecurityContext, fch:FClientHello, ?fp:fragmentationPolicy): state * nextSecurityContext * FClientKeyExchange =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        FlexClientKeyExchange.sendRSA(st,nsc,fch.pv,fp)

    (* Send ClientKeyExchange for RSA ciphersuites, compute the PMS, MS, KEYS and update the nextSecurityContext with the protocol version *)
    static member sendRSA (st:state, nsc:nextSecurityContext, pv:ProtocolVersion, ?fp:fragmentationPolicy): state * nextSecurityContext * FClientKeyExchange =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let st,fcke =
            if nsc.pms = FlexConstants.nullNextSecurityContext.pms then
                FlexClientKeyExchange.sendRSA(st,nsc.si.serverID,pv,fp=fp)
            else
                FlexClientKeyExchange.sendRSA(st,nsc.si.serverID,pv,nsc.pms,fp)
        in
        let nsc = FlexSecrets.fillSecrets(st,Client,nsc,fcke.kex) in
        st,nsc,fcke

    (* Send ClientKeyExchange for RSA ciphersuites *)
    static member sendRSA (st:state, certl:list<Cert.cert>, pv:ProtocolVersion, ?pms:bytes, ?fp:fragmentationPolicy) : state * FClientKeyExchange =
        let fp = defaultArg fp defaultFragmentationPolicy in
        if certl.IsEmpty then
            failwith (perror __SOURCE_FILE__ __LINE__  "Server certificate should always be present with a RSA signing cipher suite.")
        else
            match Cert.get_chain_public_encryption_key certl with
            | Error(ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(pk) ->
                let si = {nullSessionInfo with
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

    (* Receive ClientKeyExchange for DHE ciphersuites, compute the PMS, MS, KEYS and update the nextSecurityContext with the FServerKeyExchangeDHx  message *)
    static member receiveDHx (st:state, certl:list<Cert.cert>, ?fske:FServerKeyExchange, ?nsc:nextSecurityContext) : state * nextSecurityContext * FClientKeyExchange =
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let fske = defaultArg fske FlexConstants.nullFServerKeyExchangeDHx in
        let kexdh = 
            match fske.kex with
            | DH(kexdh) -> kexdh
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "key exchange mechanism should be DHx")
        in
        FlexClientKeyExchange.receiveDHx(st,certl,kexdh,nsc)

    (* Receive ClientKeyExchange for DHE ciphersuites, compute the PMS, MS, KEYS and update the nextSecurityContext with a user provided kexDH record *)
    static member receiveDHx (st:state, certl:list<Cert.cert>, ?kexdh:kexDH, ?nsc:nextSecurityContext) : state * nextSecurityContext * FClientKeyExchange =
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let kexdh = defaultArg kexdh FlexConstants.nullKexDH in
        
        let st,fcke = FlexClientKeyExchange.receiveDHE(st,certl,kexdh) in
        let nsc = FlexSecrets.fillSecrets(st,Server,nsc,fcke.kex) in
        st,nsc,fcke

    (* Receive ClientKeyExchange for DHE ciphersuites *)
    static member receiveDHE (st:state, certl:list<Cert.cert>, ?kexdh:kexDH) : state * FClientKeyExchange =
        let kexdh = defaultArg kexdh FlexConstants.nullKexDH in
        
        let (g,p),gx = kexdh.gp,kexdh.gx in
        let x = FlexSecrets.dh_to_adh p g gx kexdh.x in
        
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_client_key_exchange  ->
            (match parseClientKEXExplicit_DH p g payload with
            | Error(ad,x) -> failwith x
            | Correct(gy) ->
                let kexdh = { kexdh with gy = gy } in
                let fcke = { kex = DH(kexdh); payload = payload } in
                st,fcke
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "message type should be HT_client_key_exchange")
        

    (* Send ClientKeyExchange for DHE ciphersuites, compute the PMS, MS, KEYS and update the nextSecurityContext from a FServerKeyExchange message *)
    static member sendDHE (st:state, certl:list<Cert.cert>, ?fske:FServerKeyExchange, ?nsc:nextSecurityContext, ?fp:fragmentationPolicy) : state * nextSecurityContext * FClientKeyExchange =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let fske = defaultArg fske FlexConstants.nullFServerKeyExchangeDHx in

        let kexdh = 
            match fske.kex with
            | DH(kexdh) -> kexdh
            | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "key exchange mechanism should be DHx")
        in
        FlexClientKeyExchange.sendDHE(st,certl,kexdh,nsc,fp)

    (* Send ClientKeyExchange for DHE ciphersuites, compute the PMS, MS, KEYS and update the nextSecurityContext from a KEX record *)
    static member sendDHE (st:state, certl:list<Cert.cert>, kexdh:kexDH, ?nsc:nextSecurityContext, ?fp:fragmentationPolicy) : state * nextSecurityContext * FClientKeyExchange =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in

        let st,fcke = FlexClientKeyExchange.sendDHE(st,certl,kexdh,fp) in
        let nsc = FlexSecrets.fillSecrets(st,Client,nsc,fcke.kex) in
        st,nsc,fcke

    (* Send ClientKeyExchange for DHE ciphersuites *)
    static member sendDHE (st:state, certl:list<Cert.cert>, kexdh:kexDH, ?fp:fragmentationPolicy) : state * FClientKeyExchange =
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        
        let g,p = kexdh.gp in
        let dhp : CoreKeys.dhparams = {g = g; p = p; q=None} in
        let (x,_),(gx,_) = CoreDH.gen_key dhp in

        let payload = clientKEXExplicitBytes_DH gx in
        let st = FlexHandshake.send(st,payload,fp) in
        let kexdh = {kexdh with x = x; gx = gx } in
        let fcke = { kex = DH(kexdh); payload = payload } in
        st,fcke

    end
