﻿module MACKey

open Bytes
open Algorithms
open CipherSuites
open TLSInfo

type key = {k:bytes}

let GEN (ki) = {k= mkRandom (macKeySize (macAlg_of_ciphersuite ki.sinfo.cipher_suite))}
let COERCE (ki:KeyInfo) k = {k=k}
let LEAK (ki:KeyInfo) {k=k} = k 
