module MiHTTPChannel

open Bytes
open TLSConstants
open TLSInfo
open TLS

open MiHTTPData
open MiHTTPCookie

type channelid = bytes

type cstate = {
    channelid   : cbytes;
    hostname    : string;
    credentials : string option;
}

type request = {
    uri : string;
}

type status = {
    done_       : cdocument list;
    credentials : string option;
    cookies     : cookie list;
}

type channel = {
    channelid : cbytes;
    hostname  : string;
    lock      : MiHTTPWorker.lock;
    status    : status ref;
}

type auth =
| ACert of string

let initial_status =
    { done_ = []; credentials = None; cookies = []; }

let default_config = {
    minVer = ProtocolVersion.TLS_1p0;
    maxVer = ProtocolVersion.TLS_1p2;
    ciphersuites = cipherSuites_of_nameList [ TLS_RSA_WITH_AES_128_CBC_SHA ];
    compressions = [ NullCompression ];

    honourHelloReq = HRPFull;
    allowAnonCipherSuite = true;
    request_client_certificate = false; (* ignored *)
    check_client_version_in_pms_for_old_tls = false; (* ignored *)

    safe_renegotiation = true;
    safe_resumption = false;
    server_name = "";
    client_name = "";

    sessionDBFileName = "session-db.db";
    sessionDBExpiry   = Date.newTimeSpan 1 0 0 0 (* one day *);
}

let create_with_id (cid : channelid) (host : string) =
    let config = { default_config with server_name = host } in
    let lock   = MiHTTPWorker.create_lock () in

    { channelid   = cbytes cid;
      hostname    = host;
      lock        = lock;
      status      = ref initial_status; }

let create (host : string) =
    let cid = Nonce.random 16 in
    create_with_id cid host

let save_channel (c : channel) : cstate =
    { channelid   = Array.copy c.channelid;
      hostname    = c.hostname;
      credentials = (!c.status).credentials; }

let restore_channel (s : cstate) : channel =
    let conn = create_with_id (abytes s.channelid) s.hostname in
    conn.status := { !conn.status with credentials = s.credentials; }
    conn

let connect (h : string) =
    create h

let rec wait_handshake c =
    match TLS.read c with
    | ReadError _         -> Error.unexpected "read error"
    | Close _             -> Error.unexpected "connection closed"
    | Fatal _             -> Error.unexpected "fatal alert"
    | Warning (c, _)      -> wait_handshake c
    | CertQuery (c, q, b) ->
        match TLS.authorize c q with
        | ReadError _    -> Error.unexpected "read error"
        | Close _        -> Error.unexpected "connection closed"
        | Fatal _        -> Error.unexpected "fatal alert"
        | Warning (c, _) -> wait_handshake c
        | CertQuery _    -> Error.unexpected "cert. query"
        | Handshaken c   -> c
        | Read _         -> Error.unexpected "app. data"
        | DontWrite c    -> wait_handshake c
    | Handshaken c -> c
    | Read _       -> Error.unexpected "app. data"
    | DontWrite c -> wait_handshake c

let rec full_write conn rgd =
    match TLS.write conn rgd with
    | WriteError _          -> Error.unexpected "write error"
    | WriteComplete c       -> c
    | WritePartial (c, rgd) -> full_write c rgd
    | MustRead _            -> Error.unexpected "must-read"

let rec full_read conn d =
    match TLS.read conn with
    | ReadError _    -> Error.unexpected "read error"
    | Close _        -> (None, MiHTTPData.finalize d)
    | Fatal _        -> Error.unexpected "fatal alert"
    | Warning (c, _) -> full_read c d
    | CertQuery _    -> Error.unexpected "cert. query"
    | Handshaken c   -> Error.unexpected "handshaken"
    | DontWrite c    -> full_read c d
    | Read (c, (rg, x)) ->
        let epoch  = TLS.getEpochIn  c in
        let stream = TLS.getInStream c in
        let d = MiHTTPData.push_delta epoch stream rg x d in    
            full_read c d

let rec wait_for_close conn =
    match TLS.read conn with
    | ReadError _    -> Error.unexpected "read error"
    | Close _        -> ()
    | Fatal _        -> Error.unexpected "fatal alert"
    | Warning (c, _) -> wait_for_close c
    | CertQuery _    -> Error.unexpected "cert. query"
    | Handshaken c   -> Error.unexpected "handshaken"
    | Read (c, _)    -> Error.unexpected "app. data"
    | DontWrite c    -> wait_for_close c

let dorequest (c : channel) (a : auth option) (r : request) =
    let upgrade () =
        match a with
        | None -> !c.status
        | Some (ACert cn) ->
            match (!c.status).credentials with
            | None ->
                c.status := { !c.status with credentials = Some cn; }
                !c.status
            | Some cn' ->
                if cn <> cn' then Error.unexpected "inconsistent creds";
                !c.status

    let status  = MiHTTPWorker.critical c.lock upgrade () in
    let cname   = match status.credentials with None -> "" | Some cn -> cn in
    let config  = { default_config with server_name = c.hostname; client_name = cname; } in
    let conn    = Tcp.connect c.hostname 443 in
    let conn    = TLS.connect conn config in
    let document = MiHTTPData.create () in

    let conn = wait_handshake conn in

    let request =
        let epoch  = TLS.getEpochOut conn in
        let stream = TLS.getOutStream conn in
        let range  = (0, 1024) in
        (range, MiHTTPData.request epoch stream range r.uri) in

    let conn = full_write conn request in
    let conn, d = full_read conn (MiHTTPData.create ()) in

    match conn with
    | None -> ()
    | Some conn ->
        let conn = TLS.full_shutdown conn in
            ignore (wait_for_close conn)

    match d with
    | None ->
        fprintfn stderr "invalid document"
    | Some d ->
        let adddoc () =
            c.status := { !c.status with done_ = d :: (!c.status).done_; }
        in
            fprintfn stderr "valid document";
            MiHTTPWorker.critical c.lock adddoc ()

let request (c : channel) (a : auth option) (r : string) =
    let r = { uri = r; } in
    let f = (fun () -> dorequest c a r) in
    MiHTTPWorker.async f ()

let poll (c : channel) =
    let poll () =
        match (!c.status).done_ with
        | [] -> None
        | d :: ds -> c.status := { !c.status with done_ = ds }; Some d
    in
    MiHTTPWorker.critical c.lock poll ()
