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
    current : document option;
    waiting : request list;
}

type channel = {
    channelid   : cbytes;
    hostname    : string;
    credentials : string option;
    connection  : TLS.Connection;
    status      : status;
}

let initial_status =
    { current = None; waiting = []; }

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
    server_name = "";
    client_name = "";

    sessionDBFileName = "session-db.db";
    sessionDBExpiry   = Date.newTimeSpan 1 0 0 0 (* one day *);
}

let create (host : string) =
    let cid = cbytes (Nonce.random 16) in
    let config = { default_config with server_name = host } in
    let c = Tcp.connect host 443 in
    let c = TLS.connect c config in

    { channelid   = cid;
      hostname    = host;
      credentials = None;
      connection  = c;
      status      = initial_status; }

let state_of_channel (c : channel) : cstate =
    { channelid   = Array.copy c.channelid;
      hostname    = c.hostname;
      credentials = c.credentials; }

let channel_of_state (s : cstate) : channel =
    failwith "TODO"
