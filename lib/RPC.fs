module RPC

open Bytes
open TLSInfo
open Error
open DataStream
open Dispatch
open TLS

let config certname = {
    TLSInfo.minVer = CipherSuites.SSL_3p0
    TLSInfo.maxVer = CipherSuites.TLS_1p2

    TLSInfo.ciphersuites =
        CipherSuites.cipherSuites_of_nameList [
            CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA256;
            CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA;
            CipherSuites.TLS_RSA_WITH_3DES_EDE_CBC_SHA;
        ]

    TLSInfo.compressions = [ CipherSuites.NullCompression ]

    (* Client side *)
    TLSInfo.honourHelloReq = TLSInfo.HRPResume
    TLSInfo.allowAnonCipherSuite = false

    (* Server side *)
    TLSInfo.request_client_certificate = true
    TLSInfo.check_client_version_in_pms_for_old_tls = true
    TLSInfo.safe_renegotiation = true

    TLSInfo.server_cert_file = certname
    TLSInfo.certificateValidationPolicy = (fun _ -> true)

    TLSInfo.sessionDBFileName = "sessionDBFile.bin"
    TLSInfo.sessionDBExpiry = Bytes.newTimeSpan 2 0 0 0 (* two days *)
}

let msglen = 128

let padmsg = fun r ->
    if Bytes.length r > msglen then
        fst (Bytes.split r msglen)
    else
        r @| (Bytes.createBytes (msglen - (Bytes.length r)) 0)

let request_bytes  nonce r = nonce @| (padmsg r)
let response_bytes nonce r = nonce @| (padmsg r)

let service = fun r -> r

type DrainResult =
| DRError    of ioerror
| DRClosed   of Tcp.NetworkStream
| DRContinue of Connection

let rec drainMeta = fun conn ->
  match TLS.read conn with
  | ReadError  e         -> DRError e
  | Close      s         -> DRClosed s
  | Fatal      e         -> DRError (EFatal e)
  | Warning    (conn, _) -> DRContinue conn
  | CertQuery  (conn, q) -> DRContinue (authorize conn q)
  | Handshaken conn      -> DRContinue conn
  | DontWrite  conn      -> drainMeta conn
  | Read       (conn, _) ->
        ignore (TLS.shutdown conn)
        DRError (EInternal (Error.TLS, Error.InvalidState))

let rec sendMsg = fun conn rg msg ->
    match TLS.write conn (rg, msg) with
    | WriteError    e                 -> None
    | WriteComplete conn              -> Some conn
    | WritePartial  (conn, (rg, msg)) -> sendMsg conn rg msg
    | MustRead      conn              ->
        match drainMeta conn with
        | DRError    _    -> None
        | DRClosed   _    -> None
        | DRContinue conn -> sendMsg conn rg msg

let recvMsg = fun conn ->
    let rec doit = fun conn buffer ->
        match TLS.read conn with
          | ReadError  _              -> None
          | Close      _              -> None
          | Fatal      _              -> None
          | Warning    (conn, _)      -> doit conn buffer
          | CertQuery  (conn, q)      -> doit (authorize conn q) buffer
          | Handshaken conn           -> doit conn buffer
          | DontWrite  conn           -> doit conn buffer
          | Read       (conn, (r, d)) ->
                let ki     = Dispatch.getEpochIn  conn in
                let s      = TLS.getInStream conn in
                let buffer = buffer @| (DataStream.deltaRepr ki s r d) in

                if Bytes.length buffer < 2+msglen then
                    doit conn buffer
                elif Bytes.length buffer > 2+msglen then
                    ignore (TLS.shutdown conn); None
                else
                    Some (conn, buffer)
                    
    in
        doit conn [||]

let doclient (request : string) =
    let options = config "client" in

    let ns      = Tcp.connect "127.0.0.1" 5000 in
    let conn    = TLS.connect ns options in

    match drainMeta conn with
    | DRError  _ -> None
    | DRClosed _ -> None

    | DRContinue conn ->
        let nonce   = Bytes.mkRandom 2 in
        let request = request_bytes nonce (Bytes.utf8 request) in

        let msg =
            DataStream.createDelta
                (Dispatch.getEpochOut conn) (TLS.getOutStream conn)
                (Bytes.length request, Bytes.length request) request in

        match sendMsg conn (Bytes.length request, Bytes.length request) msg with
        | Some conn ->
            match recvMsg conn with
            | None -> None
            | Some (conn, response) ->
                ignore (TLS.shutdown conn);

                if Bytes.length response <> 2+msglen then
                    None
                else
                    let rnonce, response = Bytes.split response 2 in
                        if Bytes.equalBytes nonce rnonce then
                            Some (Bytes.iutf8 response)
                        else
                            None
        | None -> None

let doserver () =
    let options = config "server" in

    let ns = Tcp.listen "127.0.0.1" 5000 in

    let rec doclient = fun () ->
        let client = Tcp.accept ns in

        let result =
            let conn = TLS.accept_connected client options in

            match drainMeta conn with
            | DRError  _ -> false
            | DRClosed _ -> false
            | DRContinue conn ->
                match recvMsg conn with
                | None -> false
                | Some (conn, request) ->
                    if Bytes.length request < 2 then
                        false
                    else
                        let nonce, request = Bytes.split request 2 in
                        let response = service (Bytes.iutf8 request) in
                        let response = response_bytes nonce (Bytes.utf8 response) in

                        let msg =
                            DataStream.createDelta
                                (Dispatch.getEpochOut conn) (TLS.getOutStream conn)
                                (Bytes.length response, Bytes.length response) response in

                        match sendMsg conn (Bytes.length response, Bytes.length response) msg with
                        | Some conn -> ignore (TLS.shutdown conn); true
                        | None -> false
        in
            Tcp.close client; result
    in
        doclient ()
