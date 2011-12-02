module HMAC

open Bytes
open Algorithms
open Error

type key = bytes
type data = bytes
type mac = bytes

(* Raw hmac algorithms --
   Although in principle the libraries could throw exceptions, here
   we claim that the following functions never throw their declared
   exceptions:
   ArgumentNullException: becuase there is no null value in F# (and the arguments comes from F#)
   ObjectDisposedException: because each instance variable is always referenced *)

#if fs
let hmacmd5 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACMD5 (key) in
    hmacobj.ComputeHash data

let hmacsha1 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACSHA1 (key) in
    hmacobj.ComputeHash data

let hmacsha256 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACSHA256 (key) in
    hmacobj.ComputeHash data

let hmacsha384 key (data:bytes) =
    let hmacobj = new System.Security.Cryptography.HMACSHA384 (key) in
    hmacobj.ComputeHash data
#else
let hmacmd5   : key -> data -> mac = failwith "trusted" 
let hmacsha1  : key -> data -> mac  = failwith "trusted"
let hmacsha256: key -> data -> mac  = failwith "trusted" 
let hmacsha384: key -> data -> mac  = failwith "trusted" 
#endif

(* SSL3 keyed hash *)

let sslKeyedHash alg key data =
    let (pad1, pad2) =
        match alg with
        | MD5 -> (ssl_pad1_md5, ssl_pad2_md5)
        | SHA -> (ssl_pad1_sha1, ssl_pad2_sha1)
        | _   -> unexpectedError "[sslKeyedHash] invoked on unsupported algorithm"
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
    | MD5    -> hmacmd5 key data
    | SHA    -> hmacsha1 key data
    | SHA256 -> hmacsha256 key data
    | SHA384 -> hmacsha384 key data

let HMACVERIFY alg key data expected =
    let result = HMAC alg key data in
    equalBytes result expected