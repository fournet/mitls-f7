module TLS

open Bytes
open AppConfig
open Dispatch
open Error
open TLSInfo

(* OpenSSL style write functions. *)
(*
let write conn d =
    writeOneAppFragment conn d
    
let rec writeFully_int conn toSend sent =
    if equalBytes toSend empty_bstr then
        (correct (sent,toSend),conn)
    else
        match write conn toSend with
        | (Correct x,conn) ->
            let (frag,rem) = x in
            let new_sent = append frag sent in
            writeFully_int conn rem new_sent
        | (Error (x,y),conn) -> (Error(x,y),conn)

let writeFully conn d =
    writeFully_int conn d empty_bstr
*)

let write conn b =
    // FIXME:
    // The next three lines should be in the top level app,
    // and the write function should take appdata
    let si = getSessionInfo conn
    let lengths = (0,1) in
    let appdata = b in
    Dispatch.commit conn lengths appdata

(*
let write_buffer_empty conn =
    Dispatch.write_buffer_empty conn
*)

let flush conn =
    match writeAppData conn with
        | (Error(x,y),conn) -> (Error(x,y),conn)
        | (Correct(_),conn) -> (correct(), conn)

let read conn =
    match readAppData conn with
    | (conn,Error(x,y)) -> (conn,Error(x,y))
    | (conn,Correct(appdata)) ->
        // FIXME: next two lines should be in the top level app,
        // and the read function should return appdata
        let si = getSessionInfo conn
        (conn,correct(appdata))

(*
let dataAvailable conn =
    appDataAvailable conn
*)

let shutdown (conn:Connection) = (* TODO *) ()

let getSessionInfo conn =
    Dispatch.getSessionInfo conn

(*
let rec int_consume conn =
    let unitVal = () in
    match read conn with
    | (Correct b, conn) ->
        if length b = 0 then
            int_consume conn
        else
            unexpectedError "[int_connect] No user data should be received during the first handshake, or a synchronous re-handshake."
    | (Error(NewSessionInfo,Notification),conn) -> (correct(unitVal),conn)
    | (Error(x,y),conn) -> (Error(x,y),conn)
*)

let connect ns ops =
    let conn = Dispatch.init ns CtoS ops in
    readHS conn

let resume ns sid ops =
    match Dispatch.resume ns sid ops with
    | (Error(x,y),conn) -> (Error(x,y),conn)
    | (Correct (_), conn) -> readHS conn

let rehandshake conn ops =
    Dispatch.ask_rehandshake conn ops

let rehandshake_now conn ops =
    let conn = rehandshake conn ops in
    readHS conn

let rekey conn ops =
    Dispatch.ask_rekey conn ops

let rekey_now conn ops =
    let conn = rekey conn ops in
    readHS conn

let accept_connected ns ops =
    let conn = Dispatch.init ns StoC ops in
    readHS conn

let accept list ops =
    let ns = Tcp.accept list in
    accept_connected ns ops

let handshakeRequest conn ops =
    Dispatch.ask_hs_request conn ops

let handshakeRequest_now conn ops =
    let conn = handshakeRequest conn ops in
    readHS conn
