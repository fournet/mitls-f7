module PwApp

open Bytes
open PwToken

val request  : (*name*)string -> (*my*)string -> token -> bool
val response : unit -> (*name*)string option
