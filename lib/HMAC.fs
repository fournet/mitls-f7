module HMAC

open Bytes
open Algorithms
open Error

type key = bytes
type data = bytes
type mac = bytes

(* Raw hmac algorithms, can throw exceptions *)
let hmacmd5 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACMD5 (key) in
    hmacobj.ComputeHash (data)

let hmacsha1 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACSHA1 (key) in
    hmacobj.ComputeHash (data)

let hmacsha256 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACSHA256 (key) in
    hmacobj.ComputeHash (data)

let hmacsha384 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACSHA384 (key) in
    hmacobj.ComputeHash (data)

(* Parametric hmac wrapper *)
let HMAC alg key data =
    try
        let res = 
            match alg with
            | MD5    -> hmacmd5 key data
            | SHA    -> hmacsha1 key data
            | SHA256 -> hmacsha256 key data
            | SHA384 -> hmacsha384 key data
        correct (res)
    with
    | _ -> Error (MAC, Internal)

let HMACVERIFY alg key data expected =
    match HMAC alg key data with
    | Correct (result) ->
        if equalBytes result expected then
            correct ()
        else
            Error (MAC, CheckFailed)
    | Error (x,y) -> Error(x,y)