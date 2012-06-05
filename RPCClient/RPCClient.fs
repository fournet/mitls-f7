module RPCClient

let _ =
    let s = System.Console.ReadLine () in

    match RPC.doclient s with
    | None   -> Printf.printfn "Failure"
    | Some r -> Printf.printfn "Response: %s" r
