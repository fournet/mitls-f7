module testServer

open Error_handling

let serverAddr = "0.0.0.0"
let serverPort = 4433
let options = AppCommon.defaultProtocolOptions

open System.Security.Cryptography.X509Certificates

let rec testS_int listn =
    match TLS.accept listn options with
    | (Error(x,y),_) -> printf "AYEEEE!!! %A %A" x y
    | (Correct (_), conn) -> printf "OK; C to continue, everything else to abort"
    let resp = System.Console.ReadLine() in
    if resp = "C" then
        testS_int listn
    else
        ()

let testS =
    let listn = Tcp.listen serverAddr serverPort in
    testS_int listn
    
        