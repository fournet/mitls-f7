module RSA

open Bytes
open Error

type sk = RSASKey of bytes * bytes
type pk = RSAPKey of bytes * bytes

let create_rsapkey ((m, e) : bytes * bytes) = RSAPKey (m, e)
let create_rsaskey ((m, e) : bytes * bytes) = RSASKey (m, e)
