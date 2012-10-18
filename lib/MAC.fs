module MAC

open Bytes
open TLSConstants

open TLSInfo
//open HASH (* Only for SSL 3 keyed hash *)
open Error

type text = bytes
type tag = bytes

type key = {k:bytes}

(* generic algorithms *)

let Mac ki key data =
    let si = epochSI(ki) in
    let pv = si.protocol_version in
    let a = macAlg_of_ciphersuite si.cipher_suite in
    match pv with
    (* KB: added a when clause below. Remove it when epoch guarantees the condition as an invariant. *)
    | SSL_3p0 when a = SHA || a = MD5 -> HMAC.sslKeyedHash a key.k data 
    | TLS_1p0 | TLS_1p1 | TLS_1p2     -> HMAC.HMAC         a key.k data

let Verify ki key data tag =
    let si = epochSI(ki) in
    let pv = si.protocol_version in
    let a = macAlg_of_ciphersuite si.cipher_suite in
    match pv with
    | SSL_3p0 when a = SHA || a = MD5 -> HMAC.sslKeyedHashVerify a key.k data tag
    | TLS_1p0 | TLS_1p1 | TLS_1p2     -> HMAC.HMACVERIFY         a key.k data tag

let GEN (ki) =
    let si = epochSI(ki) in
    {k= mkRandom (macKeySize (macAlg_of_ciphersuite si.cipher_suite))}
let COERCE (ki:epoch) k = {k=k}
let LEAK (ki:epoch) {k=k} = k
