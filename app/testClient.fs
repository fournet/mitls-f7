module testClient

open Error_handling

let serverIP = "193.55.250.100"
let serverPort = 5556
let options = AppCommon.defaultProtocolOptions

let testCl () =
    let ns = Tcp.connect serverIP serverPort in
    let conn = TLS.connect ns options in
    match conn with
    | (Error(x,y),conn) ->
        Printf.printf "AYEEE!!! %A %A" x y
        ignore (System.Console.ReadLine())
        (Error(x,y),conn)
    | (unitVal,conn) ->
        Printf.printf "Full OK"
        ignore (System.Console.ReadLine())
        (unitVal,conn)

let testRes ()  =
    let ns = Tcp.connect serverIP serverPort in
    let sid = (SessionDB.getAllStoredIDs options).Head in
    printf "Asking resumption with %A" sid
    match SessionDB.select options sid with
    | None -> printf "AYEEE, expecting to resume a session!"
    | Some (sinfo) ->
        let conn = TLS.resume ns sinfo options in
        match conn with
        | (Error(x,y),_) -> Printf.printf "AYEEE!!! %A %A" x y
        | Correct(_), conn ->
            let sinfo = TLS.getSessionInfo conn in
            match sinfo.sessionID with
            | None -> printf "Full handshale, and got new, non-resumable session."
            | Some (newSid) ->
                if sid = newSid then
                    Printf.printf "Resumption OK"
                else
                    printf "Gotta Full handshake"
        ignore (System.Console.ReadLine ())

let testFullAndReKey =
    match testCl () with
    | (Error(x,y),_) -> ()
    | (_,conn) ->
    let sinfo = TLS.getSessionInfo conn in
    match sinfo.sessionID with
    | None -> printf "Non resumable session. Sorry."
    | Some (sid) ->
        printfn "Asking re-keying"
        match TLS.rekey_now conn options with
        | (Error(x,y),_) -> Printf.printf "AYEEE!!! %A %A" x y
        | Correct(_), conn ->
            let sinfo = TLS.getSessionInfo conn in
            match sinfo.sessionID with
            | None -> printf "Full handshake, and got new, non-resumable session."
            | Some (newSid) ->
                if sid = newSid then
                    Printf.printf "Re-keying OK"
                else
                    printf "Gotta Full handshake"
        ignore (System.Console.ReadLine ())

let testFullAndRehandshake =
    match testCl () with
    | (Error(x,y),_) -> ()
    | (_,conn) ->
        printfn "Asking re-handshake"
        match TLS.rehandshake_now conn options with
        | (Error(x,y),_) -> Printf.printf "AYEEE!!! %A %A" x y
        | Correct(_), conn ->
            printf "Full re-handshake OK"
            ignore (System.Console.ReadLine ())