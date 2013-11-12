module MiHTTPChannel

open Bytes
open MiHTTPData

type channelid = bytes
type channel

type cstate = {
    channelid   : cbytes;
    hostname    : string;
    credentials : string option;
}

val save_channel    : channel -> cstate
val restore_channel : cstate -> channel

val connect : string -> channel
val request : channel -> string -> unit
val poll    : channel -> document option
