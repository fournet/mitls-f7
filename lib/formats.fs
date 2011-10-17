module Formats

open Data
open Bytearray
open Error_handling

type prerole =
    | ClientRole
    | ServerRole

type role = prerole

type preContentType =
    | Change_cipher_spec
    | Alert
    | Handshake
    | Application_data
    | UnknownCT

type ContentType = preContentType

let byte_of_contentType ct =
    match ct with
    | Change_cipher_spec -> 20uy
    | Alert              -> 21uy
    | Handshake          -> 22uy
    | Application_data   -> 23uy
    | UnknownCT -> unexpectedError "Cannot convert the Unknown content type to bytes"

let contentType_of_byte b =
  match b with 
  | 20uy -> Change_cipher_spec
  | 21uy -> Alert
  | 22uy -> Handshake
  | 23uy -> Application_data
  | _    -> UnknownCT

let bytes_of_seq sn = bytes_of_int 8 sn

(*
let split_at_most data len =
    if len >= length data then
        (data,empty_bstr)
    else
        split data len
*)

(*
let rec appendList (xl:bytes list) : bytes =
    match xl with
    | [] -> empty_bstr
    | h::t -> append h (appendList t)
*)
let (@|) a b = append a b

let rec splitList (b:bytes) (il:int list) : bytes list = 
    match il with
    | [] -> [b]
    | h::t -> let (x,y) = split b h in x::(splitList y t)

let vlenBytes_of_bytes (lenSize:int) data =
    let dlength = length data in
    let len = bytes_of_int lenSize dlength in
    append len data

let bytesAndRemainder_of_vlenBytesAndReminder lenSize data =
    let (lenbytes,data) = split data lenSize in
    let len = int_of_bytes lenSize lenbytes in
    split data len


