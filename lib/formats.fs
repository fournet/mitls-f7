module Formats

open Data
open Bytearray
open Error_handling

type preContentType =
    | Change_cipher_spec
    | Alert
    | Handshake
    | Application_data
    | UnknownCT

type ContentType = preContentType

let bytes_of_contentType ct =
  bytes_of_int 1  
   (match ct with
    | Change_cipher_spec -> 20
    | Alert              -> 21
    | Handshake          -> 22
    | Application_data   -> 23
    | UnknownCT -> unexpectedError "Cannot convert the Unknown content type to bytes")

let contentType_of_bytes (b:bytes) =
  match int_of_bytes 1 b with 
  | 20 -> Change_cipher_spec
  | 21 -> Alert
  | 22 -> Handshake
  | 23 -> Application_data
  | _  -> UnknownCT

type Compression = 
  | Null
  | UnknownComp of int

let bytes_of_compression comp =
    match comp with
    | Null -> zeroCreate 1
    | UnknownComp _ -> failwith "Cannot convert the Unkown compression type to bytes"

let compression_of_bytes b =
    if length b <> 1 then failwith "Invalid length"
    let value = int_of_bytes 1 b in
    match value with
    | 0 -> Null
    | x -> UnknownComp x

let rec compressions_of_bytes_int b list =
    if length b = 0 then
        list
    else
        let (cmB,rem) = split b 1 in
        let cm = compression_of_bytes cmB in
        let list = [cm] @ list in
        compressions_of_bytes_int rem list

let compressions_of_bytes b = compressions_of_bytes_int b []

type ProtocolVersionType =
    | SSL_2p0 = 10
    | SSL_3p0 = 20
    | TLS_1p0 = 30
    | TLS_1p1 = 40
    | TLS_1p2 = 50
    | UnknownPV = -1

let bytes_of_seq sn = bytes_of_int 8 sn

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

let bytes_of_protocolVersionType pv =
    match pv with
    | ProtocolVersionType.SSL_2p0 -> [| 0uy; 2uy |]
    | ProtocolVersionType.SSL_3p0 -> [| 3uy; 0uy |]
    | ProtocolVersionType.TLS_1p0 -> [| 3uy; 1uy |]
    | ProtocolVersionType.TLS_1p1 -> [| 3uy; 2uy |]
    | ProtocolVersionType.TLS_1p2 -> [| 3uy; 3uy |]
    | _ -> unexpectedError "Cannot convert the Unknown protocol version to bytes"

let protocolVersionType_of_bytes value =
    match value with
    | [| 0uy; 2uy |] -> ProtocolVersionType.SSL_2p0
    | [| 3uy; 0uy |] -> ProtocolVersionType.SSL_3p0
    | [| 3uy; 1uy |] -> ProtocolVersionType.TLS_1p0
    | [| 3uy; 2uy |] -> ProtocolVersionType.TLS_1p1
    | [| 3uy; 3uy |] -> ProtocolVersionType.TLS_1p2
    | _ -> ProtocolVersionType.UnknownPV

(* A.6. The Security Parameters *)

type prerole =
    | ClientRole
    | ServerRole

type role = prerole

let vlenBytes_of_bytes (lenSize:int) data =
    let dlength = length data in
    let len = bytes_of_int lenSize dlength in
    append len data

let bytesAndRemainder_of_vlenBytesAndReminder lenSize data =
    let (lenbytes,data) = split data lenSize in
    let len = int_of_bytes lenSize lenbytes in
    split data len


