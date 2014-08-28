﻿#light "off"

module FlexClientKeyExchange

open Error
open TLSConstants
open HandshakeMessages
open Bytes

open FlexTypes
open FlexConstants
open FlexHandshake

let calgs_rsa = [(SA_RSA, MD5SHA1);(SA_RSA, SHA);(SA_RSA, NULL)]

type FlexClientKeyExchange =
    class

    static member receiveRSA (st:state, nsc:nextSecurityContext, ?fch:FClientHello) : state * nextSecurityContext * FClientKeyExchangeRSA =
        let pv =
            match fch with
            | None -> nsc.si.protocol_version
            | Some(fch) -> fch.pv
        in
        FlexClientKeyExchange.receiveRSA(st,nsc,pv)

   static member receiveRSA (st:state, nsc:nextSecurityContext, ?pv:ProtocolVersion) : state * nextSecurityContext * FClientKeyExchangeRSA =
        let pv = defaultArg pv nsc.si.protocol_version in
        let st,fcke = FlexClientKeyExchange.receiveRSA(st,nsc.si.serverID,pv) in
        let nsc = {nsc with pms = fcke.pms} in
        st,nsc,fcke

    static member receiveRSA (st:state, certl:list<Cert.cert>, ?pv:ProtocolVersion) : state * FClientKeyExchangeRSA =
        let check,pv =
            match pv with
            | None -> false,defaultProtocolVersion
            | Some (pv) -> true,pv
        in
        let si = {nullFSessionInfo with serverID = certl; protocol_version = pv} in
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_client_key_exchange  ->
            (match parseClientKeyExchange_RSA si payload with
            | Error (ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (encPMS) ->
                if si.serverID.IsEmpty then
                    failwith (perror __SOURCE_FILE__ __LINE__  "When the ciphersuite can encrypt the PMS, the server certificate should always be set")
                else
                    let hint = 
                        match Cert.get_hint si.serverID with
                        | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Could not find in the store a certificate chain")
                        | Some(ch) -> ch
                    in
                    let pk = 
                        match Cert.get_chain_public_encryption_key si.serverID with
                        | Error(ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
                        | Correct(pk) -> pk
                    in
                    match Cert.for_key_encryption calgs_rsa hint with
                    | None -> failwith (perror __SOURCE_FILE__ __LINE__ "Could not find in the store a certificate for the negotiated ciphersuite")
                    | Some(c,sk) ->
                        let pmsa = RSA.decrypt sk si si.protocol_version check encPMS in
                        let pmsb = PMS.leakRSA pk si.protocol_version pmsa in
                        let fcke : FClientKeyExchangeRSA = {pms = pmsb; payload = to_log } in
                        st,fcke
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "message type should be HT_client_key_exchange")
        

    static member sendRSA (st:state, nsc:nextSecurityContext, pv:ProtocolVersion, ?pms:bytes, ?fp:fragmentationPolicy) : state * nextSecurityContext * FClientKeyExchangeRSA =
        let fp = defaultArg fp defaultFragmentationPolicy in
        let st,fcke = match pms with
            | None -> FlexClientKeyExchange.sendRSA(st,nsc.si.serverID,pv,fp=fp)
            | Some(pms) -> FlexClientKeyExchange.sendRSA(st,nsc.si.serverID,pv,pms,fp)
        in
        let nsc = {nsc with pms = fcke.pms} in
        st,nsc,fcke

    static member sendRSA (st:state, certl:list<Cert.cert>, pv:ProtocolVersion, ?pms:bytes, ?fp:fragmentationPolicy) : state * FClientKeyExchangeRSA =
        if certl.IsEmpty then
            failwith (perror __SOURCE_FILE__ __LINE__  "Server certificate should always be present with a RSA signing cipher suite.")
        else
            match Cert.get_chain_public_encryption_key certl with
            | Error(ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct(pk) ->
                let fp = defaultArg fp defaultFragmentationPolicy in
                let si = {nullFSessionInfo with protocol_version = pv} in
                let pms,pmsb = match pms with
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
