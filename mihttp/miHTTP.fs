(* ------------------------------------------------------------------------ *)
open System

(* ------------------------------------------------------------------------ *)
let hostname = "pierre-yves.strub.nu"

(* ------------------------------------------------------------------------ *)
let main () =
    let channel = MiHTTPChannel.connect hostname in
    MiHTTPChannel.request channel "/"
    ignore (System.Console.ReadLine ())

(* ------------------------------------------------------------------------ *)
let () = main ()
