module HMAC

open Data
open Algorithms
open Error_handling
open TLSPlain

type macKey = bytes

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
    let data = mac_plain_to_bytes data in
    try
        let res = 
            match alg with
            | MD5    -> hmacmd5 key data
            | SHA    -> hmacsha1 key data
            | SHA256 -> hmacsha256 key data
            | SHA384 -> hmacsha384 key data
        correct (bytes_to_mac res)
    with
    | _ -> Error (MAC, Internal)

let HMACVERIFY alg key data expected =
    match HMAC alg key data with
    | Correct (result) ->
        if equalBytes (mac_to_bytes result) (mac_to_bytes expected) then
            correct ()
        else
            Error (MAC, CheckFailed)
    | Error (x,y) -> Error(x,y)