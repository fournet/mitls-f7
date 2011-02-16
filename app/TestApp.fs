module TestApp

open Formats
open Error_handling

let _ =
    let ns = Tcp.connect "alfredo.pironti.eu" 443 in
    let state = Dispatch.init ns Sessions.ClientRole Handshake.defaultProtocolOptions in
    (* Simulate a send, then a write *)
    match Dispatch.sendNextFragments state with
    | Error(x,y) -> failwith "AYEEE send"
    | Correct(state) ->
    match Dispatch.readNextAppFragment state with
    | Error(x,y) -> failwith "AYEEE recv"
    | Correct(state) -> Printf.printf "%s\n" "CORRECT"; System.Console.Read()