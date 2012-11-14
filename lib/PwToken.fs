module PwToken

open Bytes

type token = { tk : bytes }

let repr (tk : token) = tk.tk

let mk (tk : bytes) = { tk = tk }
