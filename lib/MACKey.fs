module MACKey

open Bytes
open Algorithms
open CipherSuites
open TLSInfo

type key = {bytes:bytes}

let GEN (ki) = {bytes= mkRandom (macKeySize (macAlg_of_ciphersuite ki.sinfo.cipher_suite))}
let COERCE (ki:KeyInfo) k = {bytes=k}
let LEAK (ki:KeyInfo) {bytes=k} = k 