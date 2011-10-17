module MAC

open Data
open Algorithms
open HS_ciphersuites
open TLSInfo
open HASH (* Only for SSL 3 keyed hash *)
open HMAC
open Error_handling

(* SSL 3 specific keyed hash *)
let sslKeyedHash alg key data =
    let (pad1, pad2) =
        match alg with
        | MD5 -> (ssl_pad1_md5, ssl_pad2_md5)
        | SHA -> (ssl_pad1_sha1, ssl_pad2_sha1)
        | _ -> unexpectedError "[sslKeyedHash] invoked on unsupported algorithm"
    let dataStep1 = Array.concat [key; pad1; data] in
    match hash alg dataStep1 with
    | Error(x,y) -> Error(x,y)
    | Correct(step1) ->
        let dataStep2 = Array.concat [key; pad2; step1] in
        hash alg dataStep2

let sslKeyedHashVerify alg key data expected =
    match sslKeyedHash alg key data with
    | Correct (result) ->
        if equalBytes result expected then
            correct ()
        else
            Error(MAC,CheckFailed)
    | Error(x,y) -> Error(x,y)


(* Top level functions, implemet interface *)
let MAC ki key data =
    let pv = ki.sinfo.protocol_version in
    let alg = macAlg_of_ciphersuite ki.sinfo.cipher_suite in
    match pv with
    | ProtocolVersionType.SSL_3p0 -> sslKeyedHash alg key data
    | x when x >= ProtocolVersionType.TLS_1p0 -> HMAC alg key data
    | _ -> unexpectedError "[MAC] invoked on unsupported protocol version"

let VERIFY ki key data expected =
    let pv = ki.sinfo.protocol_version in
    let alg = macAlg_of_ciphersuite ki.sinfo.cipher_suite in
    match pv with
    | ProtocolVersionType.SSL_3p0 -> sslKeyedHashVerify alg key data expected
    | x when x >= ProtocolVersionType.TLS_1p0 -> HMACVERIFY alg key data expected
    | _ -> unexpectedError "[VERIFY] invoked on unsupported protocol version"