module MiHTTPChannel

open Bytes
open TLSConstants
open TLSInfo

open MiHTTPData

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
    current     : document option;
    waiting     : request list;
    done_       : document list;
    credentials : string option;
}

type channel = {
    channelid   : cbytes;
    hostname    : string;
    connection  : TLS.Connection;
    lock        : MiHTTPWorker.lock;
    status      : status ref;
}

let initial_status =
    { current = None; waiting = []; done_ = []; credentials = None; }

let default_config = {
    minVer = ProtocolVersion.TLS_1p0;
    maxVer = ProtocolVersion.TLS_1p2;
    ciphersuites = cipherSuites_of_nameList [ TLS_RSA_WITH_AES_128_CBC_SHA ];
    compressions = [ NullCompression ];

    honourHelloReq = HRPFull;
    allowAnonCipherSuite = true;
    request_client_certificate = false; (* ignored *)
    check_client_version_in_pms_for_old_tls = false; (* ignored *)

    safe_renegotiation = false;
    safe_resumption = false
    server_name = "";
    client_name = "";

    sessionDBFileName = "session-db.db";
    sessionDBExpiry   = Date.newTimeSpan 1 0 0 0 (* one day *);
}

let create_with_id (cid : channelid) (host : string) =
    let config = { default_config with server_name = host } in
    let lock   = MiHTTPWorker.create_lock () in
    let c = Tcp.connect host 443 in
    let c = TLS.connect c config in

    { channelid   = cbytes cid;
      hostname    = host;
      connection  = c;
      lock        = lock;
      status      = ref initial_status; }

let create (host : string) =
    let cid = Nonce.random 16 in
    create_with_id cid host

let start_worker (c : channel) =
    ()

let save_channel (c : channel) : cstate =
    { channelid   = Array.copy c.channelid;
      hostname    = c.hostname;
      credentials = (!c.status).credentials; }

let restore_channel (s : cstate) : channel =
    let conn = create_with_id (abytes s.channelid) s.hostname in
    conn.status := { !conn.status with credentials = s.credentials; }
    start_worker conn; conn

let connect (h : string) =
    let conn = create h in
    start_worker conn; conn

let request (c : channel) (r : string) =
    let r = { uri = r; } in
    let addrequest () = c.status := { !c.status with waiting = r :: (!c.status).waiting } in
    MiHTTPWorker.critical c.lock addrequest ()

let poll (c : channel) =
    let poll () =
        match (!c.status).done_ with
        | [] -> None
        | d :: ds -> c.status := { !c.status with done_ = ds }; Some d
    in

    MiHTTPWorker.critical c.lock poll ()
