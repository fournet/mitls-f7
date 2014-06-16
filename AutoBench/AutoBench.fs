(* ------------------------------------------------------------------------ *)
let entry () =
    let server = async { BenchServer.entry true }   
    let client = async {
        do! Async.Sleep 3000
        BenchClient.entry ()
    }

    [client; server]
        |> Seq.ofList
        |> Async.Parallel
        |> Async.Ignore
        |> Async.RunSynchronously

(* ------------------------------------------------------------------------ *)
[<EntryPoint>]
let main _ =
    entry ();
    printfn "<enter> to exit...";
    ignore (System.Console.ReadLine ());
    0

