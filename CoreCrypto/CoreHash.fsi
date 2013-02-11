module CoreHash

type engine

val name   : engine -> string
val update : engine -> byte array -> unit
val hash   : engine -> byte array
val reset  : engine -> unit

val md5engine    : unit -> engine
val sha1engine   : unit -> engine
val sha256engine : unit -> engine
val sha384engine : unit -> engine
val sha512engine : unit -> engine

val md5    : byte array -> byte array
val sha1   : byte array -> byte array
val sha256 : byte array -> byte array
val sha384 : byte array -> byte array
val sha512 : byte array -> byte array
