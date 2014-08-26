#light "off"

module FlexCertificate

open Tcp
open Bytes
open Error
open TLSInfo
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexHandshake




type FlexCertificate = 
    class

    (* Receive a Certificate message from the network stream *)
    static member receive (st:state) (role:Role) (nsc:nextSecurityContext) : state * nextSecurityContext * FCertificate =
        let si = nsc.si in
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_certificate  ->  
            (match parseClientOrServerCertificate payload with
            | Error (ad,x) -> failwith x
            | Correct (chain) -> 
                let cert = { nullFCertificate with chain = chain; } in
                match role with
                | Client ->
                    let si  = { si with 
                                client_auth = true;
                                clientID = chain;
                    } in
                    let nsc = { nsc with si = si } in
                    (st,nsc,cert)
                | Server ->
                    let si  = { si with 
                                serverID = chain;
                    } in
                    let nsc = { nsc with si = si } in
                    (st,nsc,cert)
            )
        | _ -> failwith "recvCertificate : message type should be HT_certificate"

    (* Send a Certificate message to the network stream using User provided chain of certificates *)
    static member send (st:state, role:Role, ?nsc:nextSecurityContext, ?fcrt:FCertificate, ?fp:fragmentationPolicy) : state * nextSecurityContext * FCertificate =
        let ns = st.ns in
        let fp = defaultArg fp defaultFragmentationPolicy in
        let fcrt = defaultArg fcrt nullFCertificate in
        let nsc = defaultArg nsc nullNextSecurityContext in

        let chain = fcrt.chain in
        let si = nsc.si in
        let msgb = HandshakeMessages.serverCertificateBytes chain in
        let st = FlexHandshake.send(st,HT_client_hello,msgb,fp) in

        // FIXME : Payload is set to msgb instead of to_log
        let si =
            match role with
            | Client ->   { si with 
                            clientID = chain;
                            client_auth = true;
                          }
            | Server -> { si with serverID = chain }
        in
        let nsc = { nsc with si = si } in
        let fcrt = { fcrt with 
                        chain = chain;
                        payload = msgb
        } in
        st,nsc,fcrt

    (* Send a Certificate message with a Cert.chain provided by the user *)
    static member send (st:state, role:Role, chain:Cert.chain, ?nsc:nextSecurityContext, ?fp:fragmentationPolicy) : state * nextSecurityContext * FCertificate =
        let nsc = defaultArg nsc nullNextSecurityContext in
        let fp = defaultArg fp defaultFragmentationPolicy in
        let fcrt = {nullFCertificate with chain = chain} in
        FlexCertificate.send(st,role,fcrt=fcrt,nsc=nsc,fp=fp)

    end
