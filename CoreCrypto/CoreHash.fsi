module CoreHash

type engine

val name   : engine -> string
val update : engine -> byte[] -> unit
val hash   : engine -> byte[]
val reset  : engine -> unit

val md5engine    : unit -> engine
val sha1engine   : unit -> engine
val sha256engine : unit -> engine
val sha384engine : unit -> engine
val sha512engine : unit -> engine

val md5    : byte[] -> byte[]
val sha1   : byte[] -> byte[]
val sha256 : byte[] -> byte[]
val sha384 : byte[] -> byte[]
val sha512 : byte[] -> byte[]
