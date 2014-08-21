#light "off"

module FlexTLS

open Tcp
open Bytes
open TLS
open TLSInfo
open TLSConstants

open FlexTypes
open FlexConnection
open FlexClientHello
open FlexServerHello




type FlexTLS =
    class

    (* Establish the TCP connection depending on the role and returning state (which includes the network stream) and configuration *)
    static member openConnection (role:Role,address:string,?oport:int) : state * config =
        let port = defaultArg oport FlexConnection.defaultPort in
        match role with
        | Client -> FlexConnection.clientOpenTcpConnection (address, port)
        | Server -> FlexConnection.serverOpenTcpConnection (address, port)

    (* TODO : Create top-level functions here like doFullHandshake or doAbreviatedHandshake that
              use the lower level functions of FlexClientHello, FlexServerHello ... etc... *)


    (* Run a full Handshake *)
    static member fullHandshake (role:Role) (st:state) : state * nextSecurityContext * FHSMessages =
    
        let sms = nullFHSMessages in
        match role with
        | Client -> 
            let st,nsc,fch = FlexClientHello.send(st) in
            let st,nsc,fsh = FlexServerHello.receive(st,nsc) in

            let sms = {sms with clientHello = fch; serverHello = fsh} in
            (st,nsc,sms)

        | Server ->
            let sh = nullFServerHello in
            let st,nsc,fch = FlexClientHello.receive(st) in
            let st,nsc,fsh = FlexServerHello.send(st,nsc) in

            let sms = {sms with clientHello = fch; serverHello = fsh} in
            (st,nsc,sms)
    end
