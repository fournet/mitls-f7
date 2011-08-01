module testServer

open Error_handling

let serverAddr = "0.0.0.0"
let serverPort = 4433
let options = AppCommon.defaultProtocolOptions

open System.Security.Cryptography.X509Certificates

let rec testS_int listn prevSid =
    match TLS.accept listn options with
    | (Error(x,y),_) -> printf "AYEEEE!!! %A %A" x y
    | (Correct (_), conn) ->
        let (kind,sid) =
            let sinfo = TLS.getSessionInfo conn in
            match sinfo.sessionID with
            | None -> ("full",Bytearray.empty_bstr)
            | Some(sid) ->
                if sid = prevSid then
                    "resumption",sid
                else
                    "full",sid
        printfn "%s OK;" kind
        printfn "A to accept new connection"
        printfn "R to ask renegotiation on this connection"
        printfn "everything else to abort"
        let resp = System.Console.ReadLine() in
        match resp with
        | "A" -> testS_int listn sid
        | "R" ->
            match TLS.handshakeRequest_now conn options with
            | (Error(x,y),_) ->
                printf "Renegotiation AYEEE!!! %A %A" x y
                ignore (System.Console.ReadLine())
            | (Correct (_),conn) ->
                printf "OK"
                ignore (System.Console.ReadLine())
        | _ -> ()

let testS =
    let listn = Tcp.listen serverAddr serverPort in
    testS_int listn Bytearray.empty_bstr
    
        