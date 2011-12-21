module Mac

open Bytes
open Algorithms
open CipherSuites
//open TLSInfo
open HASH (* Only for SSL 3 keyed hash *)
open Error

type id = TLSInfo.KeyInfo

let keysize (ki:id) = macKeySize (macAlg_of_ciphersuite ki.sinfo.cipher_suite)
type keybytes = bytes
type key = {bytes:keybytes}

let tagsize (ki:id) = macSize (macAlg_of_ciphersuite ki.sinfo.cipher_suite)
type tag = bytes

type text = bytes

(* generic algorithms *)

let MAC (ki:id) key data =
    let pv = ki.sinfo.protocol_version in
    let a = macAlg_of_ciphersuite ki.sinfo.cipher_suite in
    match pv with
    | ProtocolVersion.SSL_3p0 ->     HMAC.sslKeyedHash a key.bytes data
    | ProtocolVersion.TLS_1p0 | ProtocolVersion.TLS_1p1 | ProtocolVersion.TLS_1p2 -> HMAC.HMAC a key.bytes data

let VERIFY (ki:id) key data tag =
    let pv = ki.sinfo.protocol_version in
    let a = macAlg_of_ciphersuite ki.sinfo.cipher_suite in
    match pv with
    | ProtocolVersion.SSL_3p0 ->     HMAC.sslKeyedHashVerify a key.bytes data tag
    | ProtocolVersion.TLS_1p0 | ProtocolVersion.TLS_1p1 | ProtocolVersion.TLS_1p2 -> HMAC.HMACVERIFY a key.bytes data tag

let GEN (id:id) = {bytes= Bytes.mkRandom (keysize id)}
let COERCE (id:id) k = {bytes=k}
let LEAK (id:id) {bytes=k} = k 