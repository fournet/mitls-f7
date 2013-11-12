(* ------------------------------------------------------------------------ *)
open System

(* ------------------------------------------------------------------------ *)
let hostname = "pierre-yves.strub.nu"

(* ------------------------------------------------------------------------ *)
let main () =
    let channel = MiHTTPChannel.connect hostname in
    MiHTTPChannel.request channel "/"
    let rec wait () =
        match MiHTTPChannel.poll channel with
        | None -> Async.RunSynchronously (Async.Sleep 500); wait ()
        | Some (_, d) -> fprintfn stderr "%s\n" (Bytes.iutf8 (Bytes.abytes d))
    in
        wait ()

(* ------------------------------------------------------------------------ *)
let () = main ()
