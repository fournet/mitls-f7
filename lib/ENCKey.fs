module ENCKey

open Bytes
open Algorithms
open CipherSuites
open TLSInfo

type key = {k:bytes}

let GEN (ki) = {k = mkRandom (encKeySize (encAlg_of_ciphersuite ki.sinfo.cipher_suite))}
let COERCE (ki:KeyInfo) k = {k=k}
let LEAK (ki:KeyInfo) k = k.k

type iv = bytes
type iv3 =
    | SomeIV of iv
    | NoIV of bool

let reIndexKey (oldID:KeyInfo) (newID:KeyInfo) key = {k = key.k}
let reIndexIV  (oldID:KeyInfo) (newID:KeyInfo) (iv3:iv3) =
    match iv3 with
    | SomeIV(iv) -> SomeIV(iv)
    | NoIV(x) -> NoIV(x)