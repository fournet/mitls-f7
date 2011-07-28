module testServer

open Error_handling

let serverAddr = "0.0.0.0"
let serverPort = 4433
let options = AppCommon.defaultProtocolOptions

open System.Security.Cryptography.X509Certificates

let testS =
    let listn = Tcp.listen serverAddr serverPort in
    match TLS.accept listn options with
    | (Error(x,y),_) -> printf "AYEEEE!!! %A %A" x y
    | (Correct (_), conn) -> printf "OK"
    ignore (System.Console.ReadLine())