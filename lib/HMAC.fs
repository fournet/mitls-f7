module HMAC

open Bytes
open Algorithms
open Error

type key = bytes
type data = bytes
type mac = bytes

(* Raw hmac algorithms --
   Although in principle the libraries could throw exceptions, here
   we claim that the following functions never throw their declared
   exceptions:
   ArgumentNullException: becuase there is no null value in F# (and the arguments comes from F#)
   ObjectDisposedException: because each instance variable is always referenced *)

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
    match alg with
    | MD5    -> hmacmd5 key data
    | SHA    -> hmacsha1 key data
    | SHA256 -> hmacsha256 key data
    | SHA384 -> hmacsha384 key data

let HMACVERIFY alg key data expected =
    let result = HMAC alg key data in
    equalBytes result expected