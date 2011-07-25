module testClient

open Error_handling

let testCl () =
    let ns = Tcp.connect "193.55.250.100" 4433 in
    let conn = TLS.connect ns AppCommon.defaultProtocolOptions in
    match conn with
    | (Error(x,y),_) -> Printf.printf "AYEEE!!! %A %A" x y
    | _ -> Printf.printf "Full OK"
    ignore (System.Console.ReadLine())

let testRes =
    let ns = Tcp.connect "193.55.250.100" 4433 in
    let dpo = AppCommon.defaultProtocolOptions in
    let sid = (SessionDB.getAllStoredIDs dpo).Head in
    printf "Asking resumption with %A" sid
    match SessionDB.select dpo sid with
    | None -> printf "AYEEE, expecting to resume a session!"
    | Some (sinfo) ->
        let conn = TLS.resume ns sinfo dpo in
        match conn with
        | (Error(x,y),_) -> Printf.printf "AYEEE!!! %A %A" x y
        | Correct(_), conn ->
            let sifo = TLS.getSessionInfo conn in
            match sinfo.sessionID with
            | None -> printf "DUNNO"
            | Some (newSid) ->
                if sid = newSid then
                    Printf.printf "Resumption OK"
                else
                    printf "Gotta Full handshake"
        ignore (System.Console.ReadLine ())