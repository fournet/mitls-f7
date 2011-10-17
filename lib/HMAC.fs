module HMAC

open Data
open Algorithms
open Error_handling

type macKey = bytes
type text  = bytes
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
        match alg with
        | MD5    -> correct (hmacmd5 key data)
        | SHA    -> correct (hmacsha1 key data)
        | SHA256 -> correct (hmacsha256 key data)
        | SHA384 -> correct (hmacsha384 key data)
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