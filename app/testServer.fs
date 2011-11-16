module testServer

open Error_handling
open System.IO

let serverAddr = "0.0.0.0"
let serverPort = 4433
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

let empty_sessionDB () =
    try (let allSids = SessionDB.getAllStoredIDs options in
         List.iter (fun sid -> SessionDB.remove options sid) allSids)
    with _ -> SessionDB.create options

let prepareResponse () =
    let page = File.ReadAllBytes("index_too_much_jumbo.html") in
    let ctlen = page.Length in
    let head = "HTTP/1.0 200 OK\r\nContent-Length: " + ctlen.ToString() + "\r\n\r\n" in
    let headB = Array.map (fun x -> byte x) (head.ToCharArray()) in
    let resp = Data.append headB page in
    printfn "Response header"
    printfn "%s" head
    resp

let testHTTP () =
    empty_sessionDB ()
    let options = {options with safe_renegotiation = false}
    //let options = {options with server_cert_file = "server_untrusted"} in
    let listn = Tcp.listen serverAddr serverPort in
    match TLS.accept listn options with
    | (Error(x,y),_) ->
        printf "AYEEEE!!! %A %A" x y
        ignore (System.Console.ReadLine())
    | (Correct (_), conn) ->
        match TLS.read conn with
        | (Error(x,y),_) ->
            printf "AYEEEE!!! %A %A" x y
            ignore (System.Console.ReadLine())
        | (Correct(data),conn) ->
            let dataChar = Array.map (fun x -> char x) data
            let req = System.String (dataChar) in
            printfn "Client request"
            printfn "%s" req
            if req.StartsWith("GET /") then
                (* Send response *)
                let resp = prepareResponse () in
                let conn = TLS.write conn resp in
                match TLS.flush conn with
                | (Error(x,y),_) ->
                    printf "Renegotiation AYEEE!!! %A %A" x y
                    ignore (System.Console.ReadLine())
                | (Correct (_),conn) ->
                    printf "Sending page OK"
                    ignore (System.Console.ReadLine())

                (* Empty the sessions DB, so we are sure we'll do a full handshake *)
                empty_sessionDB ()
                (* Change the server certificate file *)
                let options = {options with server_cert_file = "server_untrusted"} in
                (* Now propose a (full) re-handshake, then give the page *)
                match TLS.handshakeRequest_now conn options with
                | (Error(x,y),_) ->
                    printf "Renegotiation AYEEE!!! %A %A" x y
                    ignore (System.Console.ReadLine())
                | (Correct (_),conn) ->
                    printf "Renegotiation OK"
                    ignore (System.Console.ReadLine())
            else
                printfn "Client invalid request"
                ignore (System.Console.ReadLine())
                TLS.shutdown conn (* Currently does nothing... *)

let putCertInFile () =
    let store = new X509Store(StoreName.My,StoreLocation.CurrentUser) in
    store.Open(OpenFlags.ReadOnly)
    let certs = store.Certificates in
    let search = certs.Find(X509FindType.FindBySubjectName,"Alfredo_Very_Untrusted",false) in
    if (search.get_Count()) < 1 then
        printfn "FAIL"
        ignore (System.Console.ReadLine () )
    else  
        let cert = search.Item(0) in
        let certBytes = cert.Export(X509ContentType.Cert) in
        let priK = cert.PrivateKey in
        let priKText = priK.ToXmlString (true) in
        System.IO.File.WriteAllBytes("server_untrusted.cer",certBytes)
        System.IO.File.WriteAllText("server_untrusted.pvk",priKText)
        printf "SUCCESS"
        ignore (System.Console.ReadLine () )