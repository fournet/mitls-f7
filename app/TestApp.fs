module TestApp

open Error_handling
open AppCommon

let expected_req = System.Text.Encoding.ASCII.GetBytes("GET /secret.key")
let canned_resp = System.Text.Encoding.ASCII.GetBytes("Some data")
let secret_resp = System.Text.Encoding.ASCII.GetBytes("Some secret data")

let clientAuthOps = defaultProtocolOptions (* Plus the option to require client auth... *)

(* Checks whether the connected client is the one we are willing to talk to *)
let valid_client_id tls = true

let flawed =
    let list = Tcp.listen "0.0.0.0" 80 in
    match TLS.accept list defaultProtocolOptions with
    | (Correct(x),tls) ->
        match TLS.read tls 15 with
        | (Correct(req),tls) ->
            if req = expected_req then
                (* We need client authentication *)
                match TLS.handshakeRequest_now tls clientAuthOps with
                | (Correct(x),tls) ->
                    if valid_client_id tls then
                        ignore (TLS.writeFully tls secret_resp)
                    else
                        failwith "Invalid client ID"
                | (Error(x,y),tls) -> failwith "Impossible to autenticate client"
            else
                (* Send canned response *)
                ignore (TLS.writeFully tls canned_resp)
        | (Error(x,y),tls) -> failwith "Cannot read from client"
    | (Error(x,y),tls) -> failwith "Impossible to set up the TLS connection"

let correct =
    let list = Tcp.listen "0.0.0.0" 80 in
    match TLS.accept list defaultProtocolOptions with
    | (Correct(x),tls) ->
        match TLS.read tls 15 with
        | (Correct(req),tls) ->
            if req = expected_req then
                (* We need client authentication *)
                match TLS.handshakeRequest_now tls clientAuthOps with
                | (Correct(x),tls) ->
                    if valid_client_id tls then
                        (* Re-read request from now-authenticated client *)
                        match TLS.read tls 15 with
                        | (Correct(req),tls) ->
                            if req = expected_req then
                                ignore (TLS.writeFully tls secret_resp)
                            else
                                failwith "Authenticated client did not confirm its request"
                        | (Error(x,y),tls) -> failwith "Cannot read from client"
                    else
                        failwith "Invalid client ID"
                | (Error(x,y),tls) -> failwith "Impossible to autenticate client"
            else
                (* Send canned response *)
                ignore (TLS.writeFully tls canned_resp)
        | (Error(x,y),tls) -> failwith "Cannot read from client"
    | (Error(x,y),tls) -> failwith "Impossible to set up the TLS connection"