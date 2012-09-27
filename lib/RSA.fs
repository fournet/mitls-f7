module RSA

open Bytes
open Error

type dk = RSASKey of bytes * bytes
type pk = RSAPKey of bytes * bytes

let create_rsaskey ((m, e) : bytes * bytes) = RSASKey (m, e)
let create_rsapkey ((m, e) : bytes * bytes) = RSAPKey (m, e)

