module Mac

open Bytes
open Algorithms
open CipherSuites
//open TLSInfo
open HASH (* Only for SSL 3 keyed hash *)
open Error

type id = {ki:TLSInfo.KeyInfo; tlen:int}

let tagsize (id:id) = macSize (macAlg_of_ciphersuite id.ki.sinfo.cipher_suite)

(* generic algorithms *)

let MAC (id:id) key data =
    let pv = id.ki.sinfo.protocol_version in
    let a = macAlg_of_ciphersuite id.ki.sinfo.cipher_suite in
    let k = MACKey.LEAK id.ki key
    let b = MACPlain.reprMACPlain id.ki data
    match pv with
    | SSL_3p0 ->     MACPlain.MACed id.ki (HMAC.sslKeyedHash a k b)
    | TLS_1p0 | TLS_1p1 | TLS_1p2 -> MACPlain.MACed id.ki (HMAC.HMAC a k b)

let VERIFY (id:id) key data tag =
    let pv = id.ki.sinfo.protocol_version in
    let a = macAlg_of_ciphersuite id.ki.sinfo.cipher_suite in
    let k = MACKey.LEAK id.ki key
    let d = MACPlain.reprMACPlain id.ki data
    let t = MACPlain.reprMACed id.ki tag
    match pv with
    | SSL_3p0 ->     HMAC.sslKeyedHashVerify a k d t
    | TLS_1p0 | TLS_1p1 | TLS_1p2 -> HMAC.HMACVERIFY a k d t