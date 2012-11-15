module PwApp

open Bytes
open PwToken

val request  : (*servname*)string ->  token -> bool
val response : (*servname*)string -> (*name*)string option
