module HASH

open Bytes
open Algorithms

(* Parametric hash algorithm (implements interface) *)
let hash alg data =
    match alg with
    | MD5    -> CoreHash.md5    data
    | SHA    -> CoreHash.sha1   data
    | SHA256 -> CoreHash.sha256 data
    | SHA384 -> CoreHash.sha384 data