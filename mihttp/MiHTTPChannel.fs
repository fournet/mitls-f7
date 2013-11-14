module MiHTTPChannel

open Bytes
open TLSConstants
open TLSInfo
open TLS

open MiHTTPData
open MiHTTPCookie

type channelid = bytes

type cstate = {
    c_channelid   : cbytes;
    c_hostname    : string;
    c_credentials : string option;
}

type hostname = string

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
    hostname  : hostname;
    lock      : MiHTTPWorker.lock;
    status    : status ref;
}

type rchannel = channel

type auth =
| ACert of string

let initial_status =
    { done_ = []; credentials = None; cookies = []; }

let create_config sname cname = {
    minVer = TLS_1p0;
    maxVer = TLS_1p2;
    ciphersuites = cipherSuites_of_nameList [ TLS_RSA_WITH_AES_128_CBC_SHA ];
    compressions = [ NullCompression ];

    honourHelloReq = HRPFull;
    allowAnonCipherSuite = true;
    request_client_certificate = false; (* ignored *)
    check_client_version_in_pms_for_old_tls = false; (* ignored *)

    safe_renegotiation = true;
    safe_resumption = false;
    server_name = sname;
    client_name = cname;

    sessionDBFileName = "session-db.db";
    sessionDBExpiry   = Date.newTimeSpan 1 0 0 0 (* one day *);
}

let create_with_id (cid : channelid) (host : hostname) : channel =
    let lock = MiHTTPWorker.create_lock () in
    { channelid   = cbytes cid;
      hostname    = host;
      lock        = lock;
      status      = ref initial_status; }

let create (host : string) =
    let cid = Nonce.random 16 in
    create_with_id cid host

let save_channel (c : channel) : cstate =
    { c_channelid   = c.channelid;
      c_hostname    = c.hostname;
      c_credentials = (!c.status).credentials; }

let restore_channel (s : cstate) : channel =
    let conn = create_with_id (abytes s.c_channelid) s.c_hostname in
    (*conn.status := { !conn.status with credentials = s.credentials; }*)
    conn

let connect (h : hostname) =
    create h

let chost (c : channel) =
    c.hostname

let rec wait_handshake (c : TLS.Connection) : TLS.Connection =
    match TLS.read c with
    | ReadError (_, _)    -> Error.unexpected "read error"
    | Close _             -> Error.unexpected "connection closed"
    | Fatal _             -> Error.unexpected "fatal alert"
    | Warning (c, _)      -> wait_handshake c
    | CertQuery (c, q, b) ->
        match TLS.authorize c q with
        | ReadError (_, _)    -> Error.unexpected "read error"
        | Close _             -> Error.unexpected "connection closed"
        | Fatal _             -> Error.unexpected "fatal alert"
        | Warning (c, _)      -> wait_handshake c
        | CertQuery (_, _, _) -> Error.unexpected "cert. query"
        | Handshaken c        -> c
        | Read (_, _)         -> Error.unexpected "app. data"
        | DontWrite c         -> wait_handshake c
    | Handshaken c -> c
    | Read (_, _)  -> Error.unexpected "app. data"
    | DontWrite c  -> wait_handshake c

let rec full_write (conn : TLS.Connection) rgd : TLS.Connection =
    match TLS.write conn rgd with
    | WriteError (_, _)     -> Error.unexpected "write error"
    | WriteComplete c       -> c
    | WritePartial (c, rgd) -> full_write c rgd
    | MustRead _            -> Error.unexpected "must-read"

let rec full_read conn d =
    match TLS.read conn with
    | ReadError (_, _)    -> Error.unexpected "read error"
    | Close _             -> (conn, MiHTTPData.finalize d)
    | Fatal _             -> Error.unexpected "fatal alert"
    | Warning (c, _)      -> full_read c d
    | CertQuery (_, _, _) -> Error.unexpected "cert. query"
    | Handshaken c        -> Error.unexpected "handshaken"
    | DontWrite c         -> full_read c d
    | Read (c, (rg, x))   ->
        let epoch  = TLS.getEpochIn  conn in
        let stream = TLS.getInStream conn in
        let d = MiHTTPData.push_delta epoch stream rg x d in    
            full_read c d

let upgrade_credentials (c : channel) (a : auth option) : status =
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

let request_of_string (conn : Connection) (r : request) =
    let epoch  = TLS.getEpochOut conn in
    let stream = TLS.getOutStream conn in
    let range  = (0, 1024) in
    (range, MiHTTPData.request epoch stream range r.uri) in

let get_cn_of_credentials (creds : string option) =
    match creds with
    | None    -> ""
    | Some cn -> cn

let add_cdocument_to_channel (c : channel) (d : cdocument) =
    c.status := { !c.status with done_ = d :: (!c.status).done_; }

let dorequest (c : channel) (a : auth option) (r : request) : unit =
#if verify
    let status = upgrade_credentials c a
#else
    let status = MiHTTPWorker.critical c.lock (fun () -> upgrade_credentials c a) () in
#endif
    let cname    = get_cn_of_credentials status.credentials in
    let config   = create_config c.hostname cname in
    let conn     = Tcp.connect c.hostname 443 in
    let conn     = TLS.connect conn config in
    let document = MiHTTPData.create () in
    let conn     = wait_handshake conn in
    let request  = request_of_string conn r in
    let conn     = full_write conn request in
    let conn, d  = full_read conn (MiHTTPData.create ()) in

    match d with
    | None   -> ()
    | Some d ->
#if verify
            add_cdocument_to_channel c d
#else
            MiHTTPWorker.critical c.lock
                (fun () -> add_cdocument_to_channel c d) ()
#endif

let request (c : channel) (a : auth option) (r : string) =
    let r = { uri = r; } in
#if verify
    dorequest c a r
#else
    let f = (fun () -> dorequest c a r) in
    MiHTTPWorker.async f ()
#endif

let dopoll (c : channel) =
    match (!c.status).done_ with
    | [] -> None
    | d :: ds -> c.status := { !c.status with done_ = ds }; Some d

let poll (c : channel) =
#if verify
    dopoll c
#else
    MiHTTPWorker.critical c.lock dopoll c
#endif
