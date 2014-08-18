#light "off"

module FlexCertificate

open Tcp
open Bytes
open Error
open TLSInfo

open FlexTypes
open FlexFragment

(* TODO : Below the client ID requires Cert.cert list but I give Cert.chain *)


(* Receive a ServerHello message from the network stream *)
let recvClientOrServerCertificate (role:Role) (ns:NetworkStream) (st:state) (si:SessionInfo) : state * SessionInfo * FCertificate =
    
    let ct,pv,len = parseFragmentHeader ns in
    let st,buf = getFragmentContent ns ct len st in
    
    let st,hstypeb,len,payload,to_log,rem = getHSMessage ns st buf in

    match HandshakeMessages.parseClientOrServerCertificate payload with
    | Error (ad,x) -> failwith x
    | Correct (certC) -> 
        let cert = { nullFCertificate with chain = certC; } in
        match role with
        | Client ->
            let si  = { si with 
                        client_auth = true;
                        clientID = certC;
            } in
            (st,si,cert)
        | Server ->
            let si  = { si with 
                        serverID = certC;
            } in
            (st,si,cert)

(* Send a ServerHello message from the network stream *)
    