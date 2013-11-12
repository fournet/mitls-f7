module MiHTTPWorker

type lock

val create_lock : unit -> lock

val async    : ('a -> unit) -> 'a -> unit
val critical : lock -> ('a -> 'b) -> 'a -> 'b
