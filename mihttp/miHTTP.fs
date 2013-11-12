(* ------------------------------------------------------------------------ *)
let hostname = "pierre-yves.strub.nu"

(* ------------------------------------------------------------------------ *)
let main () =
    let channel = MiHTTPChannel.connect hostname in
    MiHTTPChannel.request channel "/"

(* ------------------------------------------------------------------------ *)
let () = main ()
