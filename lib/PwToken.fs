module PwToken

// ------------------------------------------------------------------------
open Bytes
open Nonce
open TLSInfo
open DataStream

// ------------------------------------------------------------------------
type username = string

type token =
  | GToken of bytes
  | BToken  of bytes

type utk = UTK of username * token

type gt = GoodToken       of token
type rt = RegisteredToken of utk

// ------------------------------------------------------------------------
let MaxTkReprLen = 512

// ------------------------------------------------------------------------
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
        let utk = UTK (username, token)
        Pi.assume (RegisteredToken utk);
        tokens := utk :: !tokens

// ------------------------------------------------------------------------
let rec verify_r (utk : utk) (tokens : utk list) =
    match tokens with
    | [] -> false
    | x :: tokens -> (utk = x) || verify_r utk tokens

let verify (username : username) (token : token) =
    let utk = UTK (username, token)
    verify_r utk !tokens

// ------------------------------------------------------------------------
let guess (bytes : bytes) =
    BToken bytes

// ------------------------------------------------------------------------
type delta = DataStream.delta

// ------------------------------------------------------------------------
let tk_repr (e : epoch) (s : stream) (u : username) (tk : token) : delta =
    Error.unexpectedError ""

// ------------------------------------------------------------------------
let tk_plain (e : epoch) (s : stream) (r : range) (delta : delta) : (username * token) option =
    None
