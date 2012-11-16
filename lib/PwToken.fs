module PwToken

// ------------------------------------------------------------------------
open Bytes
open Nonce

// ------------------------------------------------------------------------
type username = string

type token =
  | GToken of bytes
  | BToken  of bytes

type gt = GoodToken of token
type rt = RegisteredToken of username * token

// ------------------------------------------------------------------------
type utk = username * token

let tokens = ref ([] : utk list)

// ------------------------------------------------------------------------
let create () =
    let token = GToken (Nonce.mkRandom 256)
    Pi.assume (GoodToken(token));
    token

// ------------------------------------------------------------------------
let register (username : username) (token : token) =
    match token with
    | BToken _  -> ()
    | GToken tk ->
        Pi.assume (RegisteredToken(username, token));
        tokens := (username, token) :: !tokens

// ------------------------------------------------------------------------
let verify (username : username) (token : token) =
    Bytes.memr !tokens (username, token)

// ------------------------------------------------------------------------
let guess (bytes : bytes) =
    BToken bytes
