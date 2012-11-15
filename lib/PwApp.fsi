module PwApp

open Bytes
open PwToken

val request  : (*servname*)string -> (*my*)string -> token -> bool
val response : (*servname*)string -> (*name*)string option
