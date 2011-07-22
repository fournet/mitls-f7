module Formats

open Data

val intpair_of_bytes: bytes -> (int*int)
val bytes_of_intpair: (int*int) -> bytes

val bytes_of_seq: int -> bytes

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

type preds =
    | PrintThis
    | FailHere

(* A.6. The Security Parameters *)

type ConnectionEnd = Client | Server
type BulkCipherAlgorithm = BCA_rc4 | BCA_des | BCA_aes_128 | BCA_aes_256 | BCA_rc2 | BCA_3des | BCA_des40 | BCA_idea | BCA_null
type CipherType = CT_stream | CT_block
type IsExportable = bool
type MACAlgorithm = MA_md5 | MA_sha1 | MA_sha256 | MA_sha384 | MA_sha512 | MA_null

type SecurityParameters = {
    cipher_type: CipherType;
    bulk_cipher_algorithm: BulkCipherAlgorithm;
    mac_algorithm: MACAlgorithm;
  }

val ssl_pad1_md5: bytes
val ssl_pad2_md5: bytes
val ssl_pad1_sha1: bytes
val ssl_pad2_sha1: bytes

val ssl_sender_client: bytes
val ssl_sender_server: bytes

val get_block_cipher_size: BulkCipherAlgorithm -> int
val get_key_cipher_size: BulkCipherAlgorithm -> int
val get_hash_size: MACAlgorithm -> int
val get_hash_key_size: MACAlgorithm -> int

val bytes_of_contentType: ContentType -> bytes
val contentType_of_bytes: bytes -> ContentType

val bytes_of_protocolVersionType: ProtocolVersionType -> bytes
val protocolVersionType_of_bytes: bytes -> ProtocolVersionType

val vlenBytes_of_bytes: int -> bytes -> bytes
val bytesAndRemainder_of_vlenBytesAndReminder: int -> bytes -> (bytes * bytes)

val compression_of_bytes: bytes -> Compression
val bytes_of_compression: Compression -> bytes

val appendList: bytes list -> bytes
val splitList: bytes -> int list -> bytes list
