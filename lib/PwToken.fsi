module PwToken

open Bytes

type token

val repr : token -> bytes
val mk   : bytes -> token
