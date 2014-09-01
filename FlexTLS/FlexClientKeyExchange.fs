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




type FlexClientKeyExchange =
    class

    (* Receive ClientKeyExchange for RSA ciphersuites *)
    static member receiveRSA (st:state, nsc:nextSecurityContext, fch:FClientHello, ?checkPV:bool) : state * nextSecurityContext * FClientKeyExchangeRSA =
        let checkPV = defaultArg checkPV true in
        FlexClientKeyExchange.receiveRSA(st,nsc,fch.pv,checkPV)

    (* Typical version of receive RSA that takes pv from FClientHello *)
    static member receiveRSA (st:state, nsc:nextSecurityContext, pv:ProtocolVersion, ?checkPV:bool) : state * nextSecurityContext * FClientKeyExchangeRSA =
        let checkPV = defaultArg checkPV true in
        let st,fcke = FlexClientKeyExchange.receiveRSA(st,nsc.si.serverID,pv,checkPV) in
        let pms = fcke.pms in
        let ms = FlexSecrets.pms_to_ms nsc.si pms in
        let er = TLSInfo.nextEpoch st.read.epoch  nsc.crand nsc.srand nsc.si in
        let ew = TLSInfo.nextEpoch st.write.epoch nsc.crand nsc.srand nsc.si in
        let keys = FlexSecrets.ms_to_keys er ew Server ms in
        let nsc = {nsc with
                    ms = ms;
                    keys = keys} in
        st,nsc,fcke

    (* Typical version of receive RSA that takes pv *)
    static member receiveRSA (st:state, certl:list<Cert.cert>, pv:ProtocolVersion, ?checkPV:bool) : state * FClientKeyExchangeRSA =
        let checkPV = defaultArg checkPV true in
        let hint = 
            match Cert.get_hint certl with
            | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Please provide a certificate")
            | Some(ch) -> ch
        in
        let sk =
            match Cert.for_key_encryption calgs_rsa hint with
            | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Please provide a certificate for which the private key is available")
            | Some(c,sk) -> sk
        in
        let pk = 
            match Cert.get_public_encryption_key certl.Head with
            | Error(ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(pk) -> pk
        in
        let si = {nullSessionInfo with serverID = certl; protocol_version = pv} in
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_client_key_exchange  ->
            (match parseClientKeyExchange_RSA si payload with
            | Error (ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (encPMS) ->
                    let pmsa = RSA.decrypt sk si si.protocol_version checkPV encPMS in
                    let pmsb = PMS.leakRSA pk si.protocol_version pmsa in
                    let fcke : FClientKeyExchangeRSA = {pms = pmsb; payload = to_log } in
                    st,fcke
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "message type should be HT_client_key_exchange")
        
    static member sendRSA (st:state, nsc:nextSecurityContext, fch:FClientHello, ?fp:fragmentationPolicy): state * nextSecurityContext * FClientKeyExchangeRSA =
        let fp = defaultArg fp defaultFragmentationPolicy in
        FlexClientKeyExchange.sendRSA(st,nsc,fch.pv,fp)

    static member sendRSA (st:state, nsc:nextSecurityContext, pv:ProtocolVersion, ?fp:fragmentationPolicy): state * nextSecurityContext * FClientKeyExchangeRSA =
        let fp = defaultArg fp defaultFragmentationPolicy in
        let st,fcke =
            if nsc.pms = nullNextSecurityContext.pms then
                FlexClientKeyExchange.sendRSA(st,nsc.si.serverID,pv,fp=fp)
            else
                FlexClientKeyExchange.sendRSA(st,nsc.si.serverID,pv,nsc.pms,fp)
        in
        let pms = fcke.pms in
        let ms = FlexSecrets.pms_to_ms nsc.si pms in
        let er = TLSInfo.nextEpoch st.read.epoch  nsc.crand nsc.srand nsc.si in
        let ew = TLSInfo.nextEpoch st.write.epoch nsc.crand nsc.srand nsc.si in
        let keys = FlexSecrets.ms_to_keys er ew Client ms in
        let nsc = {nsc with
                    pms = pms;
                    ms = ms;
                    keys = keys}
        in
        st,nsc,fcke

    static member sendRSA (st:state, certl:list<Cert.cert>, pv:ProtocolVersion, ?pms:bytes, ?fp:fragmentationPolicy) : state * FClientKeyExchangeRSA =
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
                let fcke: FClientKeyExchangeRSA = { pms = pmsb; payload = payload } in
                st,fcke
    end
