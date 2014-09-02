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

    (* Get the client certificate *)
    let chain,algs,skey =
        let hint = "*.prosecco.fr" in
        match Cert.for_signing calgs_rsa hint calgs_rsa with
        | None -> failwith "Frack"
        | Some(c,a,s) -> c,a,s
    in

    (* Establish a Tcp connection to a peer by listening or sending on a socket *)
    let st,cfg = FlexTLS.openConnection (Client,"www.inria.fr") in

    (* Ready for handshake using either one of the top-level APIs or the Flex|Message| methods *)
    let st,sms = FlexTLS.full_handshake_RSA_with_client_auth Client st chain algs skey in 

    (* Ready for application data *)
    printf "Yuppiiii! Ready for application data !\n";
    System.Console.ReadLine()
