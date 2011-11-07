module MAC

open Data
open Algorithms
open HS_ciphersuites
open TLSInfo
open HASH (* Only for SSL 3 keyed hash *)
open TLSPlain
open Error_handling

type macKey = {bytes:bytes}

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
        match hash alg dataStep2 with
        | Error(x,y) -> Error(x,y)
        | Correct(res) -> correct(res)

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
    let res =
        match pv with
        | ProtocolVersionType.SSL_3p0 -> sslKeyedHash alg key.bytes (mac_plain_to_bytes data)
        | x when x >= ProtocolVersionType.TLS_1p0 -> HMAC.HMAC alg key.bytes (mac_plain_to_bytes data)
        | _ -> unexpectedError "[MAC] invoked on unsupported protocol version"
    match res with
    | Error(x,y) -> Error(x,y)
    | Correct(b) -> correct(bytes_to_mac b)

let VERIFY ki key data expected =
    let pv = ki.sinfo.protocol_version in
    let alg = macAlg_of_ciphersuite ki.sinfo.cipher_suite in
    match pv with
    | ProtocolVersionType.SSL_3p0 -> sslKeyedHashVerify alg key.bytes (mac_plain_to_bytes data) (mac_to_bytes expected)
    | x when x >= ProtocolVersionType.TLS_1p0 -> HMAC.HMACVERIFY alg key.bytes (mac_plain_to_bytes data) (mac_to_bytes expected)
    | _ -> unexpectedError "[VERIFY] invoked on unsupported protocol version"