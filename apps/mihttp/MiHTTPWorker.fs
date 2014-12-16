module MiHTTPWorker

type lock = Lock of (unit ref)

let create_lock () = Lock (ref ())

let async (cb : 'a -> unit) (x : 'a) : unit =
    let comp = async { cb x } in
    Async.Start comp

let critical (monitor : lock) (cb : 'a -> 'b) (x : 'a) : 'b =
    lock monitor (fun () -> cb x)
