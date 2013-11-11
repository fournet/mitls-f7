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

val create  : string -> channel

val state_of_channel : channel -> cstate
val channel_of_state : cstate -> channel

(*
val request : channel -> string -> channel
val poll : channel -> document option * channel
*)
