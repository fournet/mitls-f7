module HMAC

open Bytes
open TLSConstants
open Error

type key = bytes
type data = bytes
type mac = bytes

(* SSL3 keyed hash *)

let sslKeyedHashPads alg = 
  match alg with
    | MD5 -> (ssl_pad1_md5, ssl_pad2_md5)
    | SHA -> (ssl_pad1_sha1, ssl_pad2_sha1)
    | _   -> unexpectedError "[sslKeyedHash] invoked on unsupported algorithm"

let sslKeyedHash alg key data =
    let (pad1, pad2) = sslKeyedHashPads alg in
    let dataStep1 = key @| pad1 @| data in
    let step1 = HASH.hash alg dataStep1 in
    let dataStep2 = key @| pad2 @| step1 in
    HASH.hash alg dataStep2

let sslKeyedHashVerify alg key data expected =
    let result = sslKeyedHash alg key data in
    equalBytes result expected

(* Parametric keyed hash *)

let HMAC alg key data =
    match alg with
    | MD5    -> CoreHMac.md5    key data
    | SHA    -> CoreHMac.sha1   key data
    | SHA256 -> CoreHMac.sha256 key data
    | SHA384 -> CoreHMac.sha384 key data

let HMACVERIFY alg key data expected =
    let result = HMAC alg key data in
    equalBytes result expected
