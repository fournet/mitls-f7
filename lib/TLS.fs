module TLS

open Data
open Bytearray
open AppCommon
open Dispatch
open Error_handling
open Sessions

let writeFragment conn d =
    writeOneAppFragment conn d
    
let rec writeFully_int conn toSend sent =
    if equalBytes toSend empty_bstr then
        (correct (sent,toSend),conn)
    else
        match writeFragment conn toSend with
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

let shutdown conn = (* TODO *) ()

let getSessionInfo conn =
    Dispatch.getSessionInfo conn

let rec int_connect conn =
    let unitVal = () in
    match read conn 1 with
    | (Correct b, conn) ->
        if length b = 0 then
            int_connect conn
        else
            unexpectedError "[int_connect] No user data should be received during the first handshake"
    | (Error(NewSessionInfo,Notification),conn) -> (correct(unitVal),conn)
    | (Error(x,y),conn) -> (Error(x,y),conn)

let connect ns ops =
    let conn = Dispatch.init ns ClientRole ops in
    int_connect conn

let resume ns info =
    let conn = Dispatch.resume_client ns info in
    int_connect conn