module RPC

open Bytes
open AppConfig
open Error
open TLS

let config certname = {
    AppConfig.minVer = CipherSuites.ProtocolVersion.SSL_3p0
    AppConfig.maxVer = CipherSuites.ProtocolVersion.TLS_1p2

    AppConfig.ciphersuites =
        CipherSuites.cipherSuites_of_nameList [
            CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA256;
            CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA;
            CipherSuites.TLS_RSA_WITH_3DES_EDE_CBC_SHA;
        ]

    AppConfig.compressions = [ CipherSuites.NullCompression ]

    (* Client side *)
    AppConfig.honourHelloReq = AppConfig.HRPResume
    AppConfig.allowAnonCipherSuite = false

    (* Server side *)
    AppConfig.request_client_certificate = true
    AppConfig.check_client_version_in_pms_for_old_tls = true
    AppConfig.safe_renegotiation = true

    AppConfig.server_cert_file = certname
    AppConfig.certificateValidationPolicy = (fun _ -> true)
    AppConfig.isCompatibleSession = (fun oldS newS -> oldS = newS)

    AppConfig.sessionDBFileName = "sessionDBFile.bin"
    AppConfig.sessionDBExpiry = new System.TimeSpan(2,0,0,0) (* two days *)
}

let request_bytes  nonce r = nonce @| r
let response_bytes nonce r = nonce @| r

let service = fun r -> r

let doclient request =
    let options = config "client" in

    SessionDB.create options;

    let ns      = Tcp.connect "127.0.0.1" 5000 in
    let conn    = TLS.connect ns options in

    match conn with
    | (Error(x, y), conn) -> None
    | (Correct _, conn) ->
        let nonce   = Bytes.mkRandom 2 in
        let request = request_bytes nonce (Bytes.utf8 request) in
        let conn    = TLS.write conn request in

        match TLS.flush conn with
        | (Error(x, y), conn) -> None
        | (Correct _, conn) -> 

            match TLS.read conn with
            | (conn, Error(x, y)) -> None
            | (conn, Correct response) ->
                TLS.shutdown conn;
                if Bytes.length response < 2 then
                    None
                else
                    let rnonce, response = Bytes.split response 2 in
                        if Bytes.equalBytes nonce rnonce then
                            Some (Bytes.iutf8 response)
                        else
                            None

let doserver () =
    let options = config "server" in

    SessionDB.create options;

    let ns = Tcp.listen "127.0.0.1" 5000 in

    let rec doclient = fun () ->
        let client = Tcp.accept ns in

        let result =
            match TLS.accept_connected client options with
            | (Error(x, y), conn) -> false
            | (Correct _, conn) ->
                match TLS.read conn with
                | (conn, Error(x, y)) -> false
                | (conn, Correct request) ->
                    if Bytes.length request < 2 then
                        false
                    else
                        let nonce, request = Bytes.split request 2 in
                        let response = service (Bytes.iutf8 request) in
                        let response = response_bytes nonce (Bytes.utf8 response) in

                        let conn = TLS.write conn response in

                            match TLS.flush conn with
                            | (Error(x, y), conn) -> false
                            | (Correct _, conn) -> TLS.shutdown conn; true
        in
            Tcp.close client; result
    in
        doclient ()
