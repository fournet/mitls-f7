module testClient

open Error_handling

let testCl =
    let ns = Tcp.connect "10.200.0.161" 4433 in
    let conn = TLS.connect ns AppCommon.defaultProtocolOptions in
    match conn with
    | (Error(x,y),_) -> Printf.printf "AYEEE!!! %A %A" x y
    | _ -> Printf.printf "OK"