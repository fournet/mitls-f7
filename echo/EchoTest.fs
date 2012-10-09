module EchoTest

open System

let program () =
    let args = List.ofArray (Environment.GetCommandLineArgs ()) in
        match args with
        | [_; "server"] -> EchoServer.entry ()
        | [_; "client"] -> failwith "not implements" (* TODO *)
        | _             -> failwith "Usage: echo [server|client]"

let _ = program ()
