#light "off"

module FlexTLS

open Tcp
open Bytes
open TLS
open TLSInfo
open TLSConstants

open FlexTypes
open FlexConstants
open FlexConnection
open FlexClientHello
open FlexServerHello
open FlexCertificate
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished




type FlexTLS =
    class

    (* Establish the TCP connection depending on the role and returning state (which includes the network stream) and configuration *)
    static member openConnection (role:Role, address:string, ?cn:string, ?port:int) : state * config =
        let port = defaultArg port FlexConstants.defaultTCPPort in
        let cn = defaultArg cn address in
        match role with
        | Client -> FlexConnection.clientOpenTcpConnection (address,cn,port)
        | Server -> FlexConnection.serverOpenTcpConnection (address,cn,port)

    // TODO : Create top-level functions here like doFullHandshake or doAbreviatedHandshake that use the lower level functions of FlexClientHello, FlexServerHello ... etc...


    (* Run a full Handshake RSA *)
    static member fullHandshakeRSA (role:Role) (st:state) : state * FHSMessages =
        let sms = nullFHSMessages in
        let chain = [] in
        match role with
        | Client -> 
            let st,nsc,fch   = FlexClientHello.send(st) in
            let st,nsc,fsh   = FlexServerHello.receive(st,nsc) in
            let st,nsc,fcert = FlexCertificate.receive(st,role,nsc) in
            let st,fshd      = FlexServerHelloDone.receive(st) in
            let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(st,fch.pv,nsc.si,nsc=nsc) in
            let st,fccs      = FlexCCS.send(st) in
            
            let log = fch.payload @| fsh.payload @| fcert.payload @| fshd.payload @| fcke.payload @| fccs.payload in
            let ms = PRF.coerce (msi nsc.si) nsc.ms in
            let verify_data = PRF.makeVerifyData nsc.si ms role log in
            
            let st,ff        = FlexFinished.send(st) in
            let st,sfccs     = FlexCCS.receive(st) in
            let st,sff       = FlexFinished.receive(st) in
            let sms = { sms with 
                        clientHello = fch; 
                        serverHello = fsh;
                        serverCertificate = fcert;
                        serverHelloDone = fshd;
                        clientKeyExchange = fcke;
                        clientChangeCipherSpecs = fccs;
                        clientFinished = ff;
                        serverChangeCipherSpecs = sfccs;
                        serverFinished = sff;
                        } in
            (st,sms)

        | Server ->
            let sh = nullFServerHello in
            let st,nsc,fch   = FlexClientHello.receive(st) in
            let st,nsc,fsh   = FlexServerHello.send(st,nsc) in
            let st,nsc,fcert = FlexCertificate.send(st,role,chain,nsc) in
            let st,fshd      = FlexServerHelloDone.send(st) in
            let st,nsc,fcke  = FlexClientKeyExchange.receiveRSA(st,nsc,fch.pv) in
            let st,fccs      = FlexCCS.receive(st) in
            let st,ff        = FlexFinished.receive(st) in
            let st,sfccs     = FlexCCS.send(st) in

            let log = fch.payload @| fsh.payload @| fcert.payload @| fshd.payload @| fcke.payload @| fccs.payload in
            let ms = PRF.coerce (msi nsc.si) nsc.ms in
            let verify_data = PRF.makeVerifyData nsc.si ms role log in

            let st,sff       = FlexFinished.send(st) in
            let sms = { sms with 
                        clientHello = fch; 
                        serverHello = fsh;
                        serverCertificate = fcert;
                        serverHelloDone = fshd;
                        clientKeyExchange = fcke;
                        clientChangeCipherSpecs = fccs;
                        clientFinished = ff;
                        serverChangeCipherSpecs = sfccs;
                        serverFinished = sff;
                        } in
            (st,sms)
    end
