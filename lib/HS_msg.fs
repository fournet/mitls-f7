module HS_msg

open Bytes
open Formats
//open Record
open CipherSuites
open TLSInfo
open Principal
open Error

(*** Following RFC5246 A.4 *)

type HandShakeType =
    | HT_hello_request
    | HT_client_hello
    | HT_server_hello
    | HT_certificate
    | HT_server_key_exchange
    | HT_certificate_request
    | HT_server_hello_done
    | HT_certificate_verify
    | HT_client_key_exchange
    | HT_finished
    | HT_unknown of int

let htbytes t =
    match t with
    | HT_hello_request       -> [|  0uy |] 
    | HT_client_hello        -> [|  1uy |]
    | HT_server_hello        -> [|  2uy |]
    | HT_certificate         -> [| 11uy |]
    | HT_server_key_exchange -> [| 12uy |]
    | HT_certificate_request -> [| 13uy |]
    | HT_server_hello_done   -> [| 14uy |]
    | HT_certificate_verify  -> [| 15uy |]
    | HT_client_key_exchange -> [| 16uy |]
    | HT_finished            -> [| 20uy |]
    | HT_unknown x           -> unexpectedError "Unknown handshake type"

let parseHT b = 
    match int_of_bytes b with
    |  0 -> HT_hello_request
    |  1 -> HT_client_hello
    |  2 -> HT_server_hello
    | 11 -> HT_certificate
    | 12 -> HT_server_key_exchange
    | 13 -> HT_certificate_request
    | 14 -> HT_server_hello_done
    | 15 -> HT_certificate_verify
    | 16 -> HT_client_key_exchange
    | 20 -> HT_finished
    |  x -> HT_unknown (x)

// missing Handshake and its generic formatting
// := HandShakeType(ht) @| VLBytes(3,body) 


(** A.4.1 Hello Messages *)

type helloRequest = bytes  // empty bitstring 

type Random = {time : int; rnd : bytes}

// missing SessionID, defined in TLSInfo
// missing CompressionMethod

// missing some details, e.g. ExtensionType/Data
type Extension =
    | HExt_renegotiation_info
    | HExt_unknown of bytes

let bytes_of_HExt hExt =
    match hExt with
    | HExt_renegotiation_info -> [|0xFFuy; 0x01uy|]
    | HExt_unknown (_) -> unexpectedError "Unknown extension type"

let hExt_of_bytes b =
    match b with
    | [|0xFFuy; 0x01uy|] -> HExt_renegotiation_info
    | _ -> HExt_unknown b

type clientHello = {
    client_version: ProtocolVersion;
    ch_random: Random;
    ch_session_id: sessionID;
    cipher_suites: cipherSuites;
    compression_methods: Compression list;
    extensions: bytes;
  }

type serverHello = {
    server_version: ProtocolVersion;
    sh_random: Random;
    sh_session_id: sessionID;
    cipher_suite: cipherSuite;
    compression_method: Compression;
    neg_extensions: bytes;
  }

let hashAlg_to_tls12enum ha =
    match ha with
    | Algorithms.hashAlg.MD5    -> 1
    | Algorithms.hashAlg.SHA    -> 2
    | Algorithms.hashAlg.SHA256 -> 4
    | Algorithms.hashAlg.SHA384 -> 5

let tls12enum_to_hashAlg n =
    match n with
    | 1 -> Some Algorithms.hashAlg.MD5
    | 2 -> Some Algorithms.hashAlg.SHA
    | 4 -> Some Algorithms.hashAlg.SHA256
    | 5 -> Some Algorithms.hashAlg.SHA384
    | _ -> None

type SigAlg =
    | SA_anonymous = 0
    | SA_rsa       = 1
    | SA_dsa       = 2
    | SA_ecdsa     = 3

type SigAndHashAlg = {
    SaHA_hash: Algorithms.hashAlg;
    SaHA_signature: SigAlg;
    }


(** A.4.2 Server Authentication and Key Exchange Messages *)

type certificate = { certificate_list: cert list }

(* Server Key Exchange *)
(* TODO *)

(* Certificate Request *)
type ClientCertType = bytes // of length 1, between 0 and 3
let CLT_RSA_Sign     = [| 1uy |] 
let CLT_DSS_Sign     = [| 2uy |]
let CLT_RSA_Fixed_DH = [| 3uy |]
let CLT_DSS_Fixed_DH = [| 4uy |]
(* was:
type ClientCertType =
    | CLT_RSA_Sign = 1
    | CLT_DSS_Sign = 2
    | CLT_RSA_Fixed_DH = 3
    | CLT_DSS_Fixed_DH = 4
*)

(*
type HashAlg =
    | HA_None = 0
    | HA_md5 = 1
    | HA_sha1 = 2
    | HA_sha224 = 3
    | HA_sha256 = 4
    | HA_sha384 = 5
    | HA_sha512 = 6
*)

type certificateRequest = {
    client_certificate_type: ClientCertType list
    signature_and_hash_algorithm: (SigAndHashAlg list) Option (* Some(x) for TLS 1.2, None for previous versions *)
    certificate_authorities: string list
    }

type serverHelloDone = bytes // empty bistring


(** A.4.3 Client Authentication and Key Exchange Messages *) 

type preMasterSecret =
    { pms_client_version : ProtocolVersion; (* Highest version supported by the client *)
      pms_random: bytes }

type clientKeyExchange =
    | EncryptedPreMasterSecret of bytes (* encryption of PMS *)
    | ClientDHPublic (* TODO *)

(* Certificate Verify *)

type certificateVerify = bytes (* digital signature of all messages exchanged until now *)


(** A.4.4 Handshake Finalization Message *)

type finished = bytes