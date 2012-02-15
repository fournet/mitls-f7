module MAC

open Bytes
open Algorithms
open CipherSuites
open TLSInfo
open HASH (* Only for SSL 3 keyed hash *)
open Error

type text = bytes
type mac = bytes

type key = {k:bytes}

(* generic algorithms *)

let MAC ki key data =
    let pv = ki.sinfo.protocol_version in
    let a = macAlg_of_ciphersuite ki.sinfo.cipher_suite in
    match pv with
    | SSL_3p0 ->     HMAC.sslKeyedHash a key.k data
    | TLS_1p0 | TLS_1p1 | TLS_1p2 -> HMAC.HMAC a key.k data

let VERIFY ki key data tag =
    let pv = ki.sinfo.protocol_version in
    let a = macAlg_of_ciphersuite ki.sinfo.cipher_suite in
    match pv with
    | SSL_3p0 ->     HMAC.sslKeyedHashVerify a key.k data tag
    | TLS_1p0 | TLS_1p1 | TLS_1p2 -> HMAC.HMACVERIFY a key.k data tag

let GEN (ki) = {k= mkRandom (macKeySize (macAlg_of_ciphersuite ki.sinfo.cipher_suite))}
let COERCE (ki:KeyInfo) k = {k=k}
let LEAK (ki:KeyInfo) {k=k} = k

let reIndex (oldKI:KeyInfo) (newKI:KeyInfo) key = {k = key.k}