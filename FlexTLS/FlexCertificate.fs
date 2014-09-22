#light "off"

module FlexCertificate

open Bytes
open Error
open TLSInfo
open HandshakeMessages

open FlexTypes
open FlexConstants
open FlexHandshake




type FlexCertificate = 
    class

    /// <summary>
    /// Receive a Certificate message from the network stream
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="role"> Behaviour is either Client or Server </param>
    /// <param name="nsc"> Optional Next security context object updated with new data </param>
    /// <returns> Updated state * next security context * FCertificate message </returns>
    static member receive (st:state, role:Role, ?nsc:nextSecurityContext) : state * nextSecurityContext * FCertificate =
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let si = nsc.si in
        let st,hstype,payload,to_log = FlexHandshake.getHSMessage(st) in
        match hstype with
        | HT_certificate  ->  
            (match parseClientOrServerCertificate payload with
            | Error (ad,x) -> failwith (perror __SOURCE_FILE__ __LINE__ x)
            | Correct (chain) -> 
                let cert : FCertificate = { chain = chain; payload = to_log } in
                match role with
                | Server ->
                    let si  = { si with 
                                client_auth = true;
                                clientID = chain;
                    } in
                    let nsc = { nsc with si = si } in
                    (st,nsc,cert)
                | Client ->
                    let si  = { si with 
                                serverID = chain;
                    } in
                    let nsc = { nsc with si = si } in
                    (st,nsc,cert)
            )
        | _ -> failwith (perror __SOURCE_FILE__ __LINE__ "message type should be HT_certificate")


    /// <summary>
    /// Prepare a Certificate message bytes but doesn't send it
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="role"> Behaviour is either Client or Server </param>
    /// <param name="nsc"> Next security context object updated with new data </param>
    /// <param name="fcrt"> Optional Certificate message </param>
    /// <returns> Certificate message bytes * Updated state * Next security context</returns>
    static member prepare (st:state, role:Role, ?nsc:nextSecurityContext, ?fcrt:FCertificate) : bytes * state * nextSecurityContext * FCertificate =
        let fcrt = defaultArg fcrt FlexConstants.nullFCertificate in
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let chain = fcrt.chain in
        let si = nsc.si in
        let payload = HandshakeMessages.serverCertificateBytes chain in
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
                        payload = payload
        } in
        payload,st,nsc,fcrt

    /// <summary>
    /// Send a Certificate message to the network stream using User provided chain of certificates
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="role"> Behaviour is either Client or Server </param>
    /// <param name="nsc"> Next security context object updated with new data </param>
    /// <param name="fcrt"> Optional Certificate message </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * next security context * FCertificate message </returns>
    static member send (st:state, role:Role, ?nsc:nextSecurityContext, ?fcrt:FCertificate, ?fp:fragmentationPolicy) : state * nextSecurityContext * FCertificate =
        let ns = st.ns in
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let fcrt = defaultArg fcrt FlexConstants.nullFCertificate in
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in

        let chain = fcrt.chain in
        let si = nsc.si in
        // serverCertificateBytes actually works for both sides
        let payload = HandshakeMessages.serverCertificateBytes chain in
        let st = FlexHandshake.send(st,payload,fp) in

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
                        payload = payload
        } in
        st,nsc,fcrt

    /// <summary>
    /// Send a Certificate message to the network stream using User provided chain of certificates
    /// </summary>
    /// <param name="st"> State of the current Handshake </param>
    /// <param name="role"> Behaviour is either Client or Server </param>
    /// <param name="chain"> Certificate chain that will be send over the network </param>
    /// <param name="nsc"> Optional Next security context object updated with new data </param>
    /// <param name="fp"> Optional fragmentation policy at the record level </param>
    /// <returns> Updated state * next security context * FCertificate message </returns>
    static member send (st:state, role:Role, chain:Cert.chain, ?nsc:nextSecurityContext, ?fp:fragmentationPolicy) : state * nextSecurityContext * FCertificate =
        let nsc = defaultArg nsc FlexConstants.nullNextSecurityContext in
        let fp = defaultArg fp FlexConstants.defaultFragmentationPolicy in
        let fcrt = {FlexConstants.nullFCertificate with chain = chain} in
        FlexCertificate.send(st,role,fcrt=fcrt,nsc=nsc,fp=fp)

    end
