module PwToken

open Bytes

type token

val repr   : token -> string * bytes
val mk     : string -> bytes -> token
val bytes  : token -> bytes
val parse  : bytes -> token option
val verify : token -> b:bool{b => GoodToken(token)}

val create : _:(){GoodClient} -> tk:token{GoodToken(tk)}
val gen : () -> tk:token{not GoodToken(tk)}
