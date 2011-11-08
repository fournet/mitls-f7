module TLS

open Data
open Bytearray
open AppCommon
open Dispatch
open Error_handling
open TLSInfo

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

let read conn len =
    readOneAppFragment conn len

let dataAvailable conn =
    appDataAvailable conn

let shutdown (conn:Connection) = (* TODO *) ()

let getSessionInfo conn =
    Dispatch.getSessionInfo conn

let rec int_consume conn =
    let unitVal = () in
    match read conn 1 with
    | (Correct b, conn) ->
        if length b = 0 then
            int_consume conn
        else
            unexpectedError "[int_connect] No user data should be received during the first handshake, or a synchronous re-handshake."
    | (Error(NewSessionInfo,Notification),conn) -> (correct(unitVal),conn)
    | (Error(x,y),conn) -> (Error(x,y),conn)

let connect ns ops =
    let conn = Dispatch.init ns ClientRole ops in
    int_consume conn

let resume ns sid ops =
    match Dispatch.resume ns sid ops with
    | (Error(x,y),conn) -> (Error(x,y),conn)
    | (Correct (_), conn) -> int_consume conn

let rehandshake conn ops =
    Dispatch.ask_rehandshake conn ops

let rehandshake_now conn ops =
    let conn = rehandshake conn ops in
    int_consume conn

let rekey conn ops =
    Dispatch.ask_rekey conn ops

let rekey_now conn ops =
    let conn = rekey conn ops in
    int_consume conn

let accept list ops =
    let ns = Tcp.accept list in
    let conn = Dispatch.init ns ServerRole ops in
    int_consume conn

let handshakeRequest conn ops =
    Dispatch.ask_hs_request conn ops

let handshakeRequest_now conn ops =
    let conn = handshakeRequest conn ops in
    int_consume conn