module MACKey

open Bytes
open Algorithms
open CipherSuites
open TLSInfo

let keysize (ki) = macKeySize (macAlg_of_ciphersuite ki.sinfo.cipher_suite)
type key = {bytes:bytes}

let GEN (ki) = {bytes= mkRandom (keysize ki)}
let COERCE (ki:KeyInfo) k = {bytes=k}
let LEAK (ki:KeyInfo) {bytes=k} = k 