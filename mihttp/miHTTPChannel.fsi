module MiHTTPChannel

open Bytes
open MiHTTPData

type channelid = bytes
type channel

type auth =
| ACert of string

type cstate = {
    channelid   : cbytes;
    hostname    : string;
    credentials : string option;
}

val save_channel    : channel -> cstate
val restore_channel : cstate -> channel

val connect : string -> channel
val request : channel -> auth option -> string -> unit
val poll    : channel -> cdocument option
