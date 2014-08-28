#light "off"

module FlexClientKeyExchange

open Error
open TLSConstants
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexHandshake

let calgs_rsa = [(SA_RSA, MD5SHA1);(SA_RSA, SHA);(SA_RSA, NULL)]

type FlexClientKeyExchange =
    class

    static member receiveRSA (st:state, ?fch:FClientHello, ?nsc:nextSecurityContext) : state * nextSecurityContext * FClientKeyExchange =
        let nsc = defaultArg nsc nullNextSecurityContext in
        let si = nsc.si in

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
                        let check,chpv = 
                            match fch with
                            | None -> false,nullFClientHello.pv
                            | Some (fch) -> true,fch.pv
                        in
                        let pmsa = RSA.decrypt sk si si.protocol_version check encPMS in
                        let pmsb = PMS.leakRSA pk si.protocol_version pmsa in
                        let nsc = { nsc with pms = pmsb} in
                        st,nsc,nullFClientKeyExchange
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__  "message type should be HT_client_key_exchange")
        



    static member sendRSA (st:state, ?nsc:nextSecurityContext, ?fcke:FClientKeyExchange, ?fp:fragmentationPolicy) : state * nextSecurityContext * FClientKeyExchange =
        let nsc = defaultArg nsc nullNextSecurityContext in
        let fcke = defaultArg fcke nullFClientKeyExchange in
        let fp = defaultArg fp defaultFragmentationPolicy in
        st,nsc,fcke

    end
