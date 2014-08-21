#light "off"

module FlexCertificate

open Tcp
open Bytes
open Error
open TLSInfo
open HandshakeMessages

open FlexTypes
open FlexFragment


(* TODO : Find another way to emmbed Role for FSessionInfo update *)

type FlexCertificate = 
    class

    (* Receive a Certificate message from the network stream *)
    static member receive (role:Role) (st:state) (si:SessionInfo) : state * SessionInfo * FCertificate =
    
        let buf = st.read_s.buffer in
        let st,hstypeb,len,payload,to_log,buf = FlexFragment.getHSMessage st buf in
    
        match parseHt hstypeb with
        | Error (ad,x) -> failwith x
        | Correct(hst) ->
            match hst with
            | HT_certificate  ->  
                (match parseClientOrServerCertificate payload with
                | Error (ad,x) -> failwith x
                | Correct (certC) -> 
                    let cert = { nullFCertificate with chain = certC; } in
                    let read_s = {st.read_s with buffer = buf } in
                    let st = {st with read_s = read_s } in
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
                )
            | _ -> failwith "recvCertificate : message type should be HT_certificate"

    (* Send a Certificate message to the network stream *)

    end
