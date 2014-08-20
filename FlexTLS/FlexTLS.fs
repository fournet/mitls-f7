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
    static member openConnection (role:Role) (address:string) (port:int) : state * config =
        match role with
        | Client -> FlexConnection.clientOpenTcpConnection address port
        | Server -> FlexConnection.serverOpenTcpConnection address port

    (* TODO : Create top-level functions here like doFullHandshake or doAbreviatedHandshake that
              use the lower level functions of FlexClientHello, FlexServerHello ... etc... *)


    (* Run a full Handshake *)
    static member fullHandshake (role:Role) (st:state) (cfg:config) : SessionInfo * state * FHSMessages =
    
        let sms = nullFHSMessages in
        match role with
        | Client -> 
            let st,si,fch = FlexClientHello.send(st) in
            let st,si,fsh = FlexServerHello.receive st si in
            (si,st,sms)

        | Server ->
            let sh = nullFServerHello in
            let st,si,fch = FlexClientHello.receive st in
            let st,si,fsh = FlexServerHello.send st si sh in
            (si,st,sms)
    end