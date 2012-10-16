module CoreHMac

type engine
type key = byte[]

val name   : engine -> string
val update : engine -> byte[] -> unit
val mac    : engine -> byte[]
val reset  : engine -> unit

val md5engine    : key -> engine
val sha1engine   : key -> engine
val sha256engine : key -> engine
val sha384engine : key -> engine
val sha512engine : key -> engine

val md5    : key -> byte[] -> byte[]
val sha1   : key -> byte[] -> byte[]
val sha256 : key -> byte[] -> byte[]
val sha384 : key -> byte[] -> byte[]
val sha512 : key -> byte[] -> byte[]
