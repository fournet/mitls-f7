module Formats

open Data

val bytes_of_seq: int -> bytes

val split_at_most: bytes -> int -> (bytes * bytes)

type preContentType =
    | Change_cipher_spec
    | Alert
    | Handshake
    | Application_data
    | UnknownCT

type ContentType = preContentType

type Compression =
    | Null
    | UnknownComp of int

type ProtocolVersionType =
    | SSL_2p0 = 10
    | SSL_3p0 = 20
    | TLS_1p0 = 30
    | TLS_1p1 = 40
    | TLS_1p2 = 50
    | UnknownPV = -1

(* A.6. The Security Parameters *)

type prerole =
    | ClientRole
    | ServerRole

type role = prerole

val ssl_pad1_md5: bytes
val ssl_pad2_md5: bytes
val ssl_pad1_sha1: bytes
val ssl_pad2_sha1: bytes

val ssl_sender_client: bytes
val ssl_sender_server: bytes

val bytes_of_contentType: ContentType -> bytes
val contentType_of_bytes: bytes -> ContentType

val bytes_of_protocolVersionType: ProtocolVersionType -> bytes
val protocolVersionType_of_bytes: bytes -> ProtocolVersionType

val vlenBytes_of_bytes: int -> bytes -> bytes
val bytesAndRemainder_of_vlenBytesAndReminder: int -> bytes -> (bytes * bytes)

val compression_of_bytes: bytes -> Compression
val bytes_of_compression: Compression -> bytes
val compressions_of_bytes: bytes -> Compression list

val appendList: bytes list -> bytes
val splitList: bytes -> int list -> bytes list
