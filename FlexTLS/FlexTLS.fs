#light "off"

module FlexTLS

open Tcp
open Bytes
open TLS
open TLSInfo
open TLSConstants



open FlexTypes
open FlexConnection



(* Establish the TCP connection depending on the role and returning network stream, state and configuration *)
let openConnection (role:Role) (address:string) (port:int) =
    match role with
    | Client -> FlexConnection.clientOpenTcpConnection address port
    | Server -> FlexConnection.serverOpenTcpConnection address port

(* TODO : Create top-level functions here like doFullHandshake or doAbreviatedHandshake that
          use the lower level functions of FlexClientHello, FlexServerHello ... etc... *)


(* Run a full Handshake *)
let fullHandshake (role:Role) (ns:NetworkStream) (st:state) (cfg:config) : SessionInfo * FHSMessages =
    
    let sms = nullFHSMessages in
    match role with
    | Client -> 
        let st,si,fch = FlexClientHello.sendClientHello ns st cfg in
        let st,si,fsh = FlexServerHello.recvServerHello ns st si in
        (si,sms)

    | Server ->
        let sh = nullFServerHello in
        let st,si,fch = FlexClientHello.recvClientHello ns st in
        let st,si,fsh = FlexServerHello.sendServerHello ns st si sh in
        (si,sms)
