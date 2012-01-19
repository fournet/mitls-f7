module ENCKey

open Bytes
open Algorithms
open CipherSuites
open TLSInfo

type key = {k:bytes}

let keysize ki = encKeySize (encAlg_of_ciphersuite ki.sinfo.cipher_suite)

let GEN (ki) = {k = mkRandom (keysize ki)}
let COERCE (ki:KeyInfo) k = {k=k}
let LEAK (ki:KeyInfo) k = k.k

let bytes_to_key b = {k = b}
type iv = bytes
type iv3 =
    | SomeIV of iv
    | NoIV of unit