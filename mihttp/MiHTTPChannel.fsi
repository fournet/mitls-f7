module MiHTTPChannel

open Bytes
open MiHTTPData

type channelid = bytes
type channel

(* Channels statically bound to a hostname *)
type rchannel = channel

type auth =
| ACert of string

type hostname = string

type cstate = {
    c_channelid   : cbytes;
    c_hostname    : hostname;
    c_credentials : string option;
}

val save_channel    : channel -> cstate
val restore_channel : cstate -> channel

val chost : channel -> hostname

val connect : hostname -> channel
val request : channel -> auth option -> string -> unit
val poll    : channel -> cdocument option
