module HASH

open Bytes
open TLSConstants

(* Parametric hash algorithm (implements interface) *)
let hash alg data =
    let data = cbytes data in
    match alg with
    | NULL    -> abytes data
    | MD5SHA1 -> (abytes (CoreHash.md5 data)) @| (abytes (CoreHash.sha1 data))
    | MD5     -> abytes (CoreHash.md5    data)
    | SHA     -> abytes(CoreHash.sha1   data)
    | SHA256  -> abytes(CoreHash.sha256 data)
    | SHA384  -> abytes(CoreHash.sha384 data)