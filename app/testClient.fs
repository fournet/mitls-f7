module testClient

open TLStream
open TLSInfo
open CipherSuites

let serverIP =  "rigoletto.polito.it" // "localhost" // 128.93.188.162
let serverPort = 443
let options = {
    minVer = TLS_1p0
    maxVer = TLS_1p0
    ciphersuites = cipherSuites_of_nameList
                    [
                      TLS_RSA_WITH_AES_128_CBC_SHA
                    ]
    compressions = [ NullCompression ]

    honourHelloReq = HRPResume
    allowAnonCipherSuite = false
    request_client_certificate = false
    check_client_version_in_pms_for_old_tls = true
    server_name = "tls.inria.fr"
    client_name = ""
    safe_renegotiation = true

    sessionDBFileName = "sessionDBFile.bin"
    sessionDBExpiry = Bytes.newTimeSpan 2 0 0 0 (* two days *)
    }

let testCl options =
    let ns = new System.Net.Sockets.TcpClient(serverIP,serverPort) in
    let TLSs = new TLStream(ns.GetStream(),options,TLSClient) in
    let req = System.Text.Encoding.ASCII.GetBytes("GET /index.html HTTP/1.0\r\n\r\n") in
    TLSs.Write(req,0,req.Length);
    let buf = Array.zeroCreate 65535 in
    let mutable i = TLSs.Read(buf,0,buf.Length) in
    while i > 0 do
        Printf.printf "%s" (System.Text.Encoding.ASCII.GetString(buf,0,i))
        i <- TLSs.Read(buf,0,buf.Length)
    done
    ignore (System.Console.ReadLine())

let test = 
    testCl options

(*
let rec consume conn =
    match TLS.read conn with
    | TLS.ReadError e ->
        match e with
        | EInternal (x,y) ->
            Printf.printf "AYEEE!!! Internal: %A %A" x y
            ignore (System.Console.ReadLine())
            None
        | EFatal x ->
            Printf.printf "AYEEE!!! Fatal: %A" x
            ignore (System.Console.ReadLine())
            None
    | TLS.Handshaken (conn) ->
        Printf.printf "Full OK"
        // ignore (System.Console.ReadLine())
        Some(conn)
    | TLS.DontWrite (conn) ->
        consume conn
    | TLS.Close(tcp) ->
        Printf.printf " Close OK"
        // ignore (System.Console.ReadLine())
        None
    | x ->
        Printf.printf "AYEEE!!! %A" x
        ignore (System.Console.ReadLine())
        None
*)

(*
let testRes options sid =
    let ns = Tcp.connect serverIP serverPort in
    printf "Asking resumption with %A" sid
    match SessionDB.select options sid with
    | None -> printf "AYEEE, expecting to resume a session!"
    | Some (sinfo) ->
        let conn = TLS.resume ns sid options in
        match conn with
        | Error(x,y) -> Printf.printf "AYEEE!!! %A %A" x y
        | Correct(conn) ->
            match consume conn with
            | None -> ()
            | Some(conn) ->
                let sinfo = TLS.getSessionInfo (TLS.getEpochIn conn) in
                match sinfo.sessionID with
                | None -> printf "Full handshake, and got new, non-resumable session."
                | Some (newSid) ->
                    if sid = newSid then
                        Printf.printf "Resumption OK"
                    else
                        printf "Gotta Full handshake"
        ignore (System.Console.ReadLine ())
*)

(*
let testFullAndReKey () =
    match testCl options with
    | (Error(x,y),_,_) -> ()
    | (_,conn,ns) ->
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
*)

(*
let testFullAndRehandshake () =
    match testCl options with
    | (Error(x,y),_,_) -> ()
    | (_,conn,ns) ->
        printfn "Asking re-handshake"
        match TLS.rehandshake_now conn options with
        | (Error(x,y),_) -> Printf.printf "AYEEE!!! %A %A" x y
        | Correct(_), conn ->
            printf "Full re-handshake OK"
            ignore (System.Console.ReadLine ())
*)

(*
let testResumptionRollbackAttack () =
    (* Do a full new session in TLS 1.1 *)
    let ops = {options with minVer = CipherSuites.TLS_1p1
                            maxVer = CipherSuites.TLS_1p1
                            safe_renegotiation = false} in
    match testCl ops with
    | (Error(x,y),_,_) -> ()
    | (_,conn,ns) ->
        let sinfo = TLS.getSessionInfo conn in
        (* TODO: we might want to close the current connection,
           but closure is still not handled in our implementation *)
        Tcp.close ns
        (* Cheat in our sinfo information, changing the protocol version to TLS 1.0 *)
        let sinfo = {sinfo with protocol_version = CipherSuites.TLS_1p0 }
        match sinfo.sessionID with
        | None -> printf "Impossible to resume session."
        | Some (sid) ->
            SessionDB.insert ops sid sinfo
            let ops = {options with minVer = Formats.TLS_1p0
                                    maxVer = Formats.TLS_1p0} in
            testRes ops sid
*)
        