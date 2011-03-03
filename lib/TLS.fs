module TLS

open Data
open Bytearray
open AppCommon
open Dispatch
open Error_handling

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

(* TODO
let connect ns ops =
    let conn = Dispatch.init ns ClientRole ops in
*)