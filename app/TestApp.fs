module TestApp

open Error_handling
open AppCommon

let _ =
    let ns = Tcp.connect "alfredo.pironti.eu" 443 in
    let state = TLS.connect ns defaultProtocolOptions in
    ()