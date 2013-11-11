module miHTTPInstance

open Bytes

type instanceid = bytes
type instance

val create : string -> instance
val find   : instanceid -> instance option
val save   : instance -> unit
