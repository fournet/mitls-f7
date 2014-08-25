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
    let st,cfg = FlexTLS.openConnection (Client,"128.93.189.207","prosecco.fr",4433) in

    (* Ready for handshake using either the top-level API or the Flex|Message| methods *)
    (* let si,st,sms = FlexTLS.fullHandshake Client st in *)
    let cfg = { cfg with 
                maxVer = TLS_1p0;
                minVer = SSL_3p0;
    } in
    let st,nsc,fch = FlexClientHello.send(st,cfg=cfg) in
    let st,nsc,fsh = FlexServerHello.receive(st,nsc) in
    let st = FlexAlert.send(st,AD_close_notify,fp=One(1)) in
    let st = FlexState.updateOutgoingHSBuffer st empty_bytes in
    let st = FlexAlert.send(st,AD_close_notify) in

    (* Ready for application data *)
    printf "Ready for application data !\n";
    System.Console.ReadLine()
