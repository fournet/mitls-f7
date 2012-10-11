module Formats

open Bytes
open Error

type preContentType =
    | Change_cipher_spec
    | Alert
    | Handshake
    | Application_data

type ContentType = preContentType

let ctBytes ct =
    match ct with
    | Change_cipher_spec -> [|20uy|]
    | Alert              -> [|21uy|]
    | Handshake          -> [|22uy|]
    | Application_data   -> [|23uy|]

let parseCT b =
    match b with 
    | [|20uy|] -> correct(Change_cipher_spec)
    | [|21uy|] -> correct(Alert)
    | [|22uy|] -> correct(Handshake)
    | [|23uy|] -> correct(Application_data)
    | _        -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

let CTtoString = function
    | Change_cipher_spec -> "CCS" 
    | Alert              -> "Alert"
    | Handshake          -> "Handshake"
    | Application_data   -> "Data"

let bytes_of_seq sn = bytes_of_int 8 sn
let seq_of_bytes b = int_of_bytes b

let vlbytes (lSize:int) b = bytes_of_int lSize (length b) @| b 

let vlsplit lSize vlb : (bytes * bytes) Result = 
    let (vl,b) = split vlb lSize 
    let l = int_of_bytes vl
    if l <= length b 
    then correct(split b l) 
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
 
let vlparse lSize vlb : bytes Result = 
    let (vl,b) = split vlb lSize 
    let l = int_of_bytes vl
    if l = length b 
    then correct b 
    else Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")

(*
let split_at_most data len =
    if len >= length data then
        (data,empty_bstr)
    else
        split data len

let rec appendList (xl:bytes list) : bytes =
    match xl with
    | [] -> empty_bstr
    | h::t -> append h (appendList t)

let rec splitList (b:bytes) (il:int list) : bytes list = 
    match il with
    | [] -> [b]
    | h::t -> let (x,y) = split b h in x::(splitList y t)
*)

type certType =
    | RSA_sign
    | DSA_sign
    | RSA_fixed_dh
    | DSA_fixed_dh

let certTypeBytes ct =
    match ct with
    | RSA_sign     -> [|1uy|]
    | DSA_sign     -> [|2uy|]
    | RSA_fixed_dh -> [|3uy|]
    | DSA_fixed_dh -> [|4uy|]

let parseCertType b =
    match b with
    | [|1uy|] -> Correct(RSA_sign)
    | [|2uy|] -> Correct(DSA_sign)
    | [|3uy|] -> Correct(RSA_fixed_dh)
    | [|4uy|] -> Correct(DSA_fixed_dh)
    | _ -> Error(AD_decode_error, perror __SOURCE_FILE__ __LINE__ "")
