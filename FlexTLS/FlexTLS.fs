#light "off"

module FlexTLS

open Tcp
open Bytes
open Error
open TLS
open TLSInfo
open TLSConstants

open FlexTypes
open FlexConstants
open FlexConnection
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexCertificateRequest
open FlexCertificateVerify
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished
open FlexState
open FlexSecrets




type FlexTLS =
    class

    (* Establish the TCP connection depending on the role and returning state (which includes the network stream) and configuration *)
    static member openConnection (role:Role, address:string, ?cn:string, ?port:int) : state * config =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let cn = defaultArg cn address in
        match role with
        | Client -> FlexConnection.clientOpenTcpConnection (address,cn,port)
        | Server -> FlexConnection.serverOpenTcpConnection (address,cn,port)


    (* Run a full Handshake RSA with server side authentication only *)
    static member full_handshake_RSA (role:Role) (st:state) (chain:Cert.chain) : state * FHSMessages =
        let sms = nullFHSMessages in
        match role with
        | Client -> 
            let st,nsc,fch   = FlexClientHello.send(st) in
            let st,nsc,fsh   = FlexServerHello.receive(st,nsc) in
            let st,nsc,fcert = FlexCertificate.receive(st,role,nsc) in
            let st,fshd      = FlexServerHelloDone.receive(st) in
            let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
            let st,fccsC      = FlexCCS.send(st) in
            
            // Start encrypting
            let st           = FlexState.installWriteKeys st nsc in
            let log          = fch.payload @| fsh.payload @| fcert.payload @| fshd.payload @| fcke.payload in
            
            let st,ffC       = FlexFinished.send(st, logRoleNSC=(log,Client,nsc)) in
            let st,fccsS     = FlexCCS.receive(st) in

            // Start decrypting
            let st           = FlexState.installReadKeys st nsc in

            let log          = log @| ffC.payload in
            let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.ms Client log in
            let st,fsf       = FlexFinished.receive(st) in
            
            // Check match of reveived log with the correct one
            if not (verify_data = fsf.verify_data) then failwith "Log message received doesn't match" else

            let sms = { sms with 
                        clientHello = fch; 
                        serverHello = fsh;
                        serverCertificate = fcert;
                        serverHelloDone = fshd;
                        clientKeyExchange = fcke;
                        clientChangeCipherSpecs = fccsC;
                        clientFinished = ffC;
                        serverChangeCipherSpecs = fccsS;
                        serverFinished = fsf;
                        } in
            (st,sms)

        | Server ->
            let st,nsc,fch   = FlexClientHello.receive(st) in
            let st,nsc,fsh   = FlexServerHello.send(st,nsc) in
            let st,nsc,fcert = FlexCertificate.send(st,role,chain,nsc) in
            let st,fshd      = FlexServerHelloDone.send(st) in
            let st,nsc,fcke  = FlexClientKeyExchange.receiveRSA(st,nsc,fch.pv) in
            let st,fccsC     = FlexCCS.receive(st) in

            // Start decrypting
            let st           = FlexState.installReadKeys st nsc in
            let st,ffC       = FlexFinished.receive(st) in
            let st,fccsS     = FlexCCS.send(st) in
            
            // Start encrypting
            let st           = FlexState.installWriteKeys st nsc in
            let log          = fch.payload @| fsh.payload @| fcert.payload @| fshd.payload @| fcke.payload @| ffC.payload in
            let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.ms Server log in
            let st,ffS       = FlexFinished.send(st,verify_data) in

            // Check match of reveived log with the correct one
            if not (verify_data = ffS.verify_data) then failwith "Log message received doesn't match" else

            let sms = { sms with 
                        clientHello = fch; 
                        serverHello = fsh;
                        serverCertificate = fcert;
                        serverHelloDone = fshd;
                        clientKeyExchange = fcke;
                        clientChangeCipherSpecs = fccsC;
                        clientFinished = ffC;
                        serverChangeCipherSpecs = fccsS;
                        serverFinished = ffS;
                        } in
            (st,sms)



    (* Run a full Handshake RSA with both server and client authentication *)
    static member full_handshake_RSA_with_client_auth (role:Role) (st:state) (chain:Cert.chain) (salg:Sig.alg) (skey:Sig.skey) : state * FHSMessages =
        let sms = nullFHSMessages in

        match role with
        | Client -> 
            let st,nsc,fch   = FlexClientHello.send(st) in
            let st,nsc,fsh   = FlexServerHello.receive(st,nsc) in
            let st,nsc,fcert = FlexCertificate.receive(st,role,nsc) in
            let st,nsc,fcreq = FlexCertificateRequest.receive(st,nsc) in
            let st,fshd      = FlexServerHelloDone.receive(st) in
            
            // Client authentication
            let st,nsc,fcertC = FlexCertificate.send(st,Client,chain,nsc) in
            let log          = fch.payload @| fsh.payload @| fcert.payload @| fcreq.payload @| fshd.payload @| fcertC.payload in
            let st,fcver     = FlexCertificateVerify.send(st,log,nsc.si.protocol_version,salg,skey) in
            
            let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
            let st,fccsC     = FlexCCS.send(st) in
            
            // Start encrypting
            let st           = FlexState.installWriteKeys st nsc in
            
            let log          = log @| fcver.payload @| fcke.payload in
            let st,ffC       = FlexFinished.send(st, logRoleNSC=(log,Client,nsc)) in
            let st,fccsS     = FlexCCS.receive(st) in

            // Start decrypting
            let st           = FlexState.installReadKeys st nsc in
            
            let log          = log @| ffC.payload in
            let verify_data  = FlexSecrets.FlexSecrets.makeVerifyData nsc.si nsc.ms role log in
            let st,ffS       = FlexFinished.receive(st) in
            
            // Check match of reveived log with the correct one
            if not (verify_data = ffS.verify_data) then failwith "Log message received doesn't match" else

            let sms = { sms with 
                        clientHello = fch; 
                        serverHello = fsh;
                        serverCertificate = fcert;
                        serverHelloDone = fshd;
                        clientKeyExchange = fcke;
                        clientChangeCipherSpecs = fccsC;
                        clientFinished = ffC;
                        serverChangeCipherSpecs = fccsS;
                        serverFinished = ffS;
                        } in
            (st,sms)

        | Server ->
            let st,nsc,fch   = FlexClientHello.receive(st) in
            let st,nsc,fsh   = FlexServerHello.send(st,nsc) in
            let st,nsc,fcert = FlexCertificate.send(st,role,chain,nsc) in
            let st,fcreq     = FlexCertificateRequest.send(st) in
            let st,fshd      = FlexServerHelloDone.send(st) in

            // Client authentication
            let st,nsc,fcertC = FlexCertificate.receive(st,Server,nsc) in
            let log          = fch.payload @| fsh.payload @| fcert.payload @| fcreq.payload @| fshd.payload @| fcertC.payload in
            let st,fcver     = FlexCertificateVerify.receive(st,nsc.si.protocol_version,fcreq.sigAlgs) in
            if not (log = fcver.payload) then failwith "Log message received doesn't match" else

            let st,nsc,fcke  = FlexClientKeyExchange.receiveRSA(st,nsc,fch.pv) in
            let st,fccsC     = FlexCCS.receive(st) in

            // Start decrypting
            let st,ffC       = FlexFinished.receive(st) in
            let st,fccsS     = FlexCCS.send(st) in

            // Start encrypting
            let log          = log @| fcver.payload @| fcke.payload @| fccsC.payload @| ffC.payload in
            let verify_data  = FlexSecrets.makeVerifyData nsc.si nsc.ms role log in

            // Check match of reveived log with the correct one
            if not (verify_data = ffC.verify_data) then failwith "Log message received doesn't match" else
            
            let st,ffS       = FlexFinished.send(st,verify_data) in
            
            let sms = { sms with 
                        clientHello = fch; 
                        serverHello = fsh;
                        serverCertificate = fcert;
                        serverHelloDone = fshd;
                        clientKeyExchange = fcke;
                        clientChangeCipherSpecs = fccsC;
                        clientFinished = ffC;
                        serverChangeCipherSpecs = fccsS;
                        serverFinished = ffS;
                        } in
            (st,sms)

    end
