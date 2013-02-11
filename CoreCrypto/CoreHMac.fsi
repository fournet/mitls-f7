module CoreHMac

type engine
type key = byte array

val name   : engine -> string
val update : engine -> byte array -> unit
val mac    : engine -> byte array
val reset  : engine -> unit

val md5engine    : key -> engine
val sha1engine   : key -> engine
val sha256engine : key -> engine
val sha384engine : key -> engine
val sha512engine : key -> engine

val md5    : key -> byte array -> byte array
val sha1   : key -> byte array -> byte array
val sha256 : key -> byte array -> byte array
val sha384 : key -> byte array -> byte array
val sha512 : key -> byte array -> byte array
