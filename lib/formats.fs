module Formats

open Data
open Bytearray

type preContentType =
    | Change_cipher_spec
    | Alert
    | Handshake
    | Application_data
    | UnknownCT

type ContentType = preContentType

type preds =
    | PrintThis
    | FailHere

(*
type ContentTypeEnum =
    | Change_cipher_spec_val = 20uy
    | Alert_val = 21uy
    | Handshake_val = 22uy
    | Application_data_val = 23uy

let bytes_of_contentType ct =
    let res = Array.zeroCreate 1 in
    match ct with
    | Change_cipher_spec -> Array.set res 0 (byte ContentTypeEnum.Change_cipher_spec_val)
    | Alert -> Array.set res 0 (byte ContentTypeEnum.Alert_val)
    | Handshake -> Array.set res 0 (byte ContentTypeEnum.Handshake_val)
    | Application_data -> Array.set res 0 (byte ContentTypeEnum.Application_data_val)
    | Unknown -> failwith "Cannot convert the Unknown content type to bytes"
    res

let contentType_of_bytes (b:bytes) =
    if b.Length <> 1 then
        failwith "Unexpected length for content type"
    else
        match  Microsoft.FSharp.Core.LanguagePrimitives.EnumOfValue<byte, ContentTypeEnum>(b.[0]) with
        | ContentTypeEnum.Change_cipher_spec_val -> Change_cipher_spec
        | ContentTypeEnum.Alert_val -> Alert
        | ContentTypeEnum.Handshake_val -> Handshake
        | ContentTypeEnum.Application_data_val -> Application_data
        | _ -> Unknown
*)

let Change_cipher_spec_val = 20
let Alert_val = 21
let Handshake_val = 22
let Application_data_val = 23


let bytes_of_contentType ct =
    match ct with
    | Change_cipher_spec -> bytes_of_int 1 Change_cipher_spec_val
    | Alert -> bytes_of_int 1 Alert_val
    | Handshake -> bytes_of_int 1 Handshake_val
    | Application_data -> bytes_of_int 1 Application_data_val
    | UnknownCT -> failwith "Cannot convert the Unknown content type to bytes"

let contentType_of_bytes (b:bytes) =
  let i = int_of_bytes 1 b in
  if i = Change_cipher_spec_val then Change_cipher_spec
  elif i = Alert_val then Alert
  elif i = Handshake_val then Handshake
  elif i = Application_data_val then Application_data
  else UnknownCT

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

type ProtocolVersionType =
    | SSL_2p0 = 10
    | SSL_3p0 = 20
    | TLS_1p0 = 30
    | TLS_1p1 = 40
    | TLS_1p2 = 50
    | UnknownPV = -1

let intpair_of_bytes (msg: bytes) : (int*int) =
  let (msg1,msg2) = split msg 1 in 
    (int_of_bytes 1 msg1, int_of_bytes 1 msg2)

let bytes_of_intpair ((i,j): (int*int)) : bytes =
  let msg1 = bytes_of_int 1 i in
  let msg2 = bytes_of_int 1 j in
    append msg1 msg2

let bytes_of_seq sn = bytes_of_int 8 sn

let rec appendList (xl:bytes list) : bytes =
    match xl with
    | [] -> empty_bstr
    | h::t -> append h (appendList t)
  
let rec splitList (b:bytes) (il:int list) : bytes list = 
    match il with
    | [] -> [b]
    | h::t -> let (x,y) = split b h in x::(splitList y t)

let SSLv2 = bytes_of_intpair (0,2)
let SSLv3 = bytes_of_intpair (3,0)
let TLS1p0 = bytes_of_intpair (3,1)
let TLS1p1 = bytes_of_intpair (3,2)
let TLS1p2 = bytes_of_intpair (3,3)

let bytes_of_protocolVersionType pv =
    match pv with
    | ProtocolVersionType.SSL_2p0 -> SSLv2
    | ProtocolVersionType.SSL_3p0 -> SSLv3
    | ProtocolVersionType.TLS_1p0 -> TLS1p0
    | ProtocolVersionType.TLS_1p1 -> TLS1p1
    | ProtocolVersionType.TLS_1p2 -> TLS1p2
    | ProtocolVersionType.UnknownPV -> failwith "Cannot convert the Unknown protocol version to bytes"
    | _ -> failwith "Cannot convert the Unknown protocol version to bytes"

let protocolVersionType_of_bytes value =
    if value = SSLv2 then
        ProtocolVersionType.SSL_2p0
    elif value = SSLv3 then
        ProtocolVersionType.SSL_3p0
    elif value = TLS1p0 then
        ProtocolVersionType.TLS_1p0
    elif value = TLS1p1 then
        ProtocolVersionType.TLS_1p1
    elif value = TLS1p2 then
        ProtocolVersionType.TLS_1p2
    else
        ProtocolVersionType.UnknownPV

(* A.6. The Security Parameters *)

type ConnectionEnd = Client | Server
type BulkCipherAlgorithm = BCA_rc4 | BCA_des | BCA_aes_128 | BCA_aes_256 | BCA_rc2 | BCA_3des | BCA_des40 | BCA_idea | BCA_null
type CipherType = CT_stream | CT_block
type IsExportable = bool
type MACAlgorithm = MA_md5 | MA_sha1 | MA_sha256 | MA_sha384 | MA_sha512 | MA_null
let get_block_cipher_size bca =
    match bca with
    | BCA_des -> 8
    | BCA_aes_128 -> 16
    | BCA_aes_256 -> 32
    | _ -> failwith "Unsupported cipher"

let get_hash_size mac_alg =
    match mac_alg with
    | MA_null -> 0
    | MA_md5 -> 16
    | MA_sha1 -> 20
    | MA_sha256 -> 32
    | MA_sha384 -> 48
    | MA_sha512 -> 64

type SecurityParameters = {
    cipher_type: CipherType;
    bulk_cipher_algorithm: BulkCipherAlgorithm;
    mac_algorithm: MACAlgorithm;
  }

(* SSLv3 constants *)
 
let ssl_pad1_md5 = createBytes 48 0x36
let ssl_pad2_md5 = createBytes 48 0x5c
let ssl_pad1_sha1 = createBytes 40 0x36
let ssl_pad2_sha1 = createBytes 40 0x5c

let ssl_sender_client = let l = List.map byte [0x43; 0x4C; 0x4E; 0x54] in Array.ofList l
let ssl_sender_server = let l = List.map byte [0x53; 0x52; 0x56; 0x52] in Array.ofList l

let vlenBytes_of_bytes (lenSize:int) data =
    let dlength = length data in
    let len = bytes_of_int lenSize dlength in
    append len data

let bytesAndRemainder_of_vlenBytesAndReminder lenSize data =
    let (lenbytes,data) = split data lenSize in
    let len = int_of_bytes lenSize lenbytes in
    split data len


