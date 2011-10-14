module MAC

open Data
open Algorithms
open HS_ciphersuites
open TLSInfo
open HASH (* Only for SSL 3 keyed hash *)
open Error_handling

type macKey = bytes
type text  = bytes
type mac = bytes

(* Raw hmac algorithms, can throw exceptions *)
let hmacmd5 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACMD5 (key) in
    hmacobj.ComputeHash (data)

let hmacsha1 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACSHA1 (key) in
    hmacobj.ComputeHash (data)

let hmacsha256 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACSHA256 (key) in
    hmacobj.ComputeHash (data)

let hmacsha384 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACSHA384 (key) in
    hmacobj.ComputeHash (data)

(* Parametric hmac wrapper *)
let hmac alg key data =
    try
        match alg with
        | MD5    -> correct (hmacmd5 key data)
        | SHA    -> correct (hmacsha1 key data)
        | SHA256 -> correct (hmacsha256 key data)
        | SHA384 -> correct (hmacsha384 key data)
    with
    | _ -> Error (MAC, Internal)

let hmacVerify alg key data expected =
    match hmac alg key data with
    | Correct (result) ->
        if equalBytes result expected then
            correct ()
        else
            Error (MAC, CheckFailed)
    | Error (x,y) -> Error(x,y)

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
    | x when x >= ProtocolVersionType.TLS_1p0 -> hmac alg key data
    | _ -> unexpectedError "[MAC] invoked on unsupported protocol version"

let VERIFY ki key data expected =
    let pv = ki.sinfo.protocol_version in
    let alg = macAlg_of_ciphersuite ki.sinfo.cipher_suite in
    match pv with
    | ProtocolVersionType.SSL_3p0 -> sslKeyedHashVerify alg key data expected
    | x when x >= ProtocolVersionType.TLS_1p0 -> hmacVerify alg key data expected
    | _ -> unexpectedError "[VERIFY] invoked on unsupported protocol version"