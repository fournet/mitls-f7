module PwToken

open Bytes

type token = Token of string * bytes

let repr (tk : token) =
    let (Token (name, tk)) = tk in (name, tk)

let mk (name : string) (tk : bytes) =
    Token (name, tk)

let bytes (tk : token) = ([||] : bytes) // FIX

let parse (bytes : bytes) = (None : token option) // FIX

let verify (tk : token) =
    false // Table lookup (FIX)

