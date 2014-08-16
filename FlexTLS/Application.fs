#light "off"

module Application

open TLSInfo
open FlexTypes


let _ =
    
    (* Initiate a record to store all exchanged Handshake messages *)
    let sms = nullFHSMessages in

    (* Establish a Tcp connection to a peer by listening or sending on a socket *)
    let ns,cfg,st = FlexTLS.openConnection Client "www.inria.fr" 443 in

    (* Ready for handshake using either the top-level API or the Flex|Message| methods *)
    let si,sms = FlexTLS.fullHandshake Client ns st cfg in   

    (* Ready for application data *)
    printf "Ready for application data !"
