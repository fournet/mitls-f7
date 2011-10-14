module HASH

open Data
open Error_handling
open Algorithms

(* Raw hash algorithms -- can throw exceptions *)
let md5Instance = System.Security.Cryptography.MD5.Create ()
let md5 (x:bytes) : bytes = md5Instance.ComputeHash x

let sha1Instance = System.Security.Cryptography.SHA1.Create ()
let sha1 (x:bytes) : bytes = sha1Instance.ComputeHash x

let sha256Instance = System.Security.Cryptography.SHA256.Create ()
let sha256 (x:bytes) : bytes = sha256Instance.ComputeHash x

let sha384Instance = System.Security.Cryptography.SHA384.Create ()
let sha384 (x:bytes) : bytes = sha384Instance.ComputeHash x

(* Parametric hash algorithm (implements interface) *)
let hash alg data =
    try
        match alg with
        | MD5    -> correct (md5 data)
        | SHA    -> correct (sha1 data)
        | SHA256 -> correct (sha256 data)
        | SHA384 -> correct (sha384 data)
    with
    | _ -> Error (Hash, Internal)