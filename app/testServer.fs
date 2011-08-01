module testServer

open Error_handling
open System.IO

let serverAddr = "0.0.0.0"
let serverPort = 443
let options = {AppCommon.defaultProtocolOptions with request_client_certificate = false}

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

let testS () =
    let listn = Tcp.listen serverAddr serverPort in
    testS_int listn Bytearray.empty_bstr
    
let testHTTP =
    let listn = Tcp.listen serverAddr serverPort in
    match TLS.accept listn options with
    | (Error(x,y),_) ->
        printf "AYEEEE!!! %A %A" x y
        ignore (System.Console.ReadLine())
    | (Correct (_), conn) ->
        match TLS.read conn 1000 with
        | (Error(x,y),_) ->
            printf "AYEEEE!!! %A %A" x y
            ignore (System.Console.ReadLine())
        | (Correct(data),conn) ->
            let dataChar = Array.map (fun x -> char x) data
            let req = System.String (dataChar) in
            printfn "Client request"
            printfn "%s" req
            if req.StartsWith("GET /") then
                (* First propose a re-handshake, then give the page *)
                match TLS.handshakeRequest_now conn options with
                | (Error(x,y),_) ->
                    printf "Renegotiation AYEEE!!! %A %A" x y
                    ignore (System.Console.ReadLine())
                | (Correct (_),conn) ->
                    let page = File.ReadAllBytes("index.html") in
                    let ctlen = page.Length in
                    let head = "HTTP/1.0 200 OK\r\nContent-Length: " + ctlen.ToString() + "\r\n\r\n" in
                    let headB = Array.map (fun x -> byte x) (head.ToCharArray()) in
                    let resp = Data.append headB page in
                    printfn "Response header"
                    printfn "%s" head
                    match TLS.writeFully conn resp with
                    | (Error(x,y),_) ->
                        printf "Renegotiation AYEEE!!! %A %A" x y
                        ignore (System.Console.ReadLine())
                    | (Correct (_),conn) ->
                        printf "Sending page OK"
                        ignore (System.Console.ReadLine())
            else
                printfn "Client invalid request"
                ignore (System.Console.ReadLine())
                TLS.shutdown conn (* Currently does nothing... *)