module PwToken

open Bytes

type token
type username = string

val create   : unit -> token
val register : username -> token -> unit
val verify   : username -> token -> bool
val guess    : bytes -> token
