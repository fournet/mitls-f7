module PwToken

open Bytes

type token

val repr   : token -> string * bytes
val mk     : string -> bytes -> token
val bytes  : token -> bytes
val parse  : bytes -> token option
val verify : token -> bool
