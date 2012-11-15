module PwApp

open Bytes
open Dispatch
open TLS
open PwToken

// ------------------------------------------------------------------------
let config (servname : string) = {
    TLSInfo.minVer = TLSConstants.TLS_1p0
    TLSInfo.maxVer = TLSConstants.TLS_1p0

    TLSInfo.ciphersuites =
        TLSConstants.cipherSuites_of_nameList [
            TLSConstants.TLS_RSA_WITH_AES_128_CBC_SHA;
            TLSConstants.TLS_RSA_WITH_3DES_EDE_CBC_SHA;
        ]

    TLSInfo.compressions = [ TLSConstants.NullCompression ]

    (* Client side *)
    TLSInfo.honourHelloReq = TLSInfo.HRPResume
    TLSInfo.allowAnonCipherSuite = false

    (* Server side *)
    TLSInfo.request_client_certificate = true
    TLSInfo.check_client_version_in_pms_for_old_tls = true
    
    (* Common *)
    TLSInfo.safe_renegotiation = true
    TLSInfo.server_name = servname
    TLSInfo.client_name = ""

    TLSInfo.sessionDBFileName = "sessionDBFile.bin"
    TLSInfo.sessionDBExpiry = Bytes.newTimeSpan 2 0 0 0 (* two days *)
}

// ------------------------------------------------------------------------
let read_server_response (c : Connection) =
    match TLS.read c with
    | ReadError  (_, _)            -> false
    | Close      _                 -> false
    | Fatal      _                 -> false
    | DontWrite  conn              -> TLS.half_shutdown conn; false
    | Warning    (conn, _)         -> TLS.half_shutdown conn; false
    | CertQuery  (conn, _, _)      -> TLS.half_shutdown conn; false
    | Handshaken conn              -> TLS.half_shutdown conn; false
    | Read       (conn, _)         -> TLS.half_shutdown conn; true

let drain (c : Connection) =
    match TLS.read c with
    | ReadError  (_, _)         -> None
    | Close      _              -> None
    | Fatal      _              -> None
    | DontWrite  c              -> Some c
    | Warning    (c, _)         -> TLS.half_shutdown c; None
    | CertQuery  (c, q, _)      -> Some (TLS.authorize c q)
    | Handshaken c              -> Some c
    | Read       (c, _)         -> TLS.half_shutdown c; None

let rec do_request (request : bytes) (c : Connection) =
    let epoch  = TLS.getEpochOut c
    let stream = TLS.getOutStream c
    let range  = (length request, length request)
    let delta  = DataStream.createDelta epoch stream range request

    match TLS.write c (range, delta) with
    | WriteError    (_, _) -> false
    | WritePartial  (c, _) -> TLS.half_shutdown c; false
    | MustRead      c      -> (match drain c with Some c -> do_request request c | None -> false)
    | WriteComplete c      -> read_server_response c

// ------------------------------------------------------------------------
let request (servname : string) (my : string) (tk : token) =
    let config = config servname
    let s = Tcp.connect "127.0.0.1" 5000
    let c = TLS.connect s config

    do_request (Bytes.utf8 my) c

// ------------------------------------------------------------------------
let rec handle_client_request (c : Connection) =
    match TLS.read c with
    | ReadError  (_, s)            -> printfn "%s" s; None
    | Close      _                 -> None
    | Fatal      _                 -> None
    | DontWrite  conn              -> None
    | Warning    (conn, _)         -> handle_client_request conn
    | CertQuery  (conn, q, advice) -> if   advice
                                      then handle_client_request (authorize conn q)
                                      else refuse conn q; None
    | Handshaken conn              -> handle_client_request conn
    | Read       (conn, m)         ->
        let (r, d) = m in
        let epoch  = TLS.getEpochIn conn in
        let stream = TLS.getInStream conn in
        let bytes  = DataStream.deltaRepr epoch stream r d in

            if length bytes <> 16 then
                None
            else
                Some (Bytes.iutf8 bytes)

// ------------------------------------------------------------------------
let response (servname : string) : string option =
    let config = config servname
    let s = Tcp.listen "0.0.0.0" 5000
    let c = TLS.accept s config

    Tcp.stop s;
    handle_client_request c
