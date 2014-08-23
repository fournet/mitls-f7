#light "off"

module Application

open TLSInfo
open TLSConstants

open FlexTLS
open FlexTypes
open FlexConstants
open FlexAlert
open FlexState
open FlexClientHello
open FlexServerHello
open FlexHandshake

open Bytes
open TLSError


let _ =
    
    (* Initiate a record to store all exchanged Handshake messages *)
    let sms = nullFHSMessages in

    (* Establish a Tcp connection to a peer by listening or sending on a socket *)
    let st,_ = FlexTLS.openConnection (Client, "www.inria.fr") in

    (* Ready for handshake using either the top-level API or the Flex|Message| methods *)
    (* let si,st,sms = FlexTLS.fullHandshake Client st in *)
    let st,nsc,fch = FlexClientHello.send(st) in
    let st,nsc,fsh = FlexServerHello.receive(st,nsc) in
    let st = FlexAlert.send(st,AD_close_notify) in

    (* Ready for application data *)
    printf "Ready for application data !\n";
    System.Console.ReadLine()
