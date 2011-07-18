module HS_msg

open Data
open Formats
open Record
open HS_ciphersuites
open Sessions
open Principal

type handshakeType =
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

val bytes_of_hs_type: handshakeType -> bytes
val hs_type_of_bytes: bytes -> handshakeType

(* Message bodies *)

(* Hello Request *)
type helloRequest = bytes (* empty bitstring *)

(* Client Hello *)
type hrandom = {time : int; rnd : bytes}

type clientHello = {
    client_version: ProtocolVersionType;
    ch_random: hrandom;
    ch_session_id: sessionID;
    cipher_suites: cipherSuites;
    compression_methods: Compression list;
    extensions: bytes;
  }

(* Server Hello *)

type serverHello = {
    server_version: ProtocolVersionType;
    sh_random: hrandom;
    sh_session_id: sessionID;
    cipher_suite: CipherSuite;
    compression_method: Compression;
    neg_extensions: bytes;
  }

(* (Server and Client) Certificate *)

type certificate = { certificate_list: pri_cert list }

(* Server Key Exchange *)
(* TODO *)

(* Certificate Request *)
type ClientCertType =
    | CLT_RSA_Sign = 1
    | CLT_DSS_Sign = 2
    | CLT_RSA_Fixed_DH = 3
    | CLT_DSS_Fixed_DH = 4

type HashAlg =
    | HA_None = 0
    | HA_md5 = 1
    | HA_sha1 = 2
    | HA_sha224 = 3
    | HA_sha256 = 4
    | HA_sha384 = 5
    | HA_sha512 = 6

type SigAlg =
    | SA_anonymous = 0
    | SA_rsa = 1
    | SA_dsa = 2
    | SA_ecdsa = 3

type SigAndHashAlg = {
    SaHA_hash: HashAlg;
    SaHA_signature: SigAlg;
    }

type certificateRequest = {
    client_certificate_type: ClientCertType list
    signature_and_hash_algorithm: (SigAndHashAlg list) Option (* Some(x) for TLS 1.2, None for previous versions *)
    certificate_authorities: string list
    }

(* Server Hello Done *)
type serverHelloDone = bytes (* empty bitstring *)

(* Client Key Exchange *)
type preMasterSecret =
    { pms_client_version : ProtocolVersionType; (* Highest version supported by the client *)
      pms_random: bytes }

type clientKeyExchange =
    | EncryptedPreMasterSecret of bytes (* encryption of PMS *)
    | ClientDHPublic (* TODO *)

(* Certificate Verify *)

type certificateVerify = bytes (* digital signature of all messages exchanged until now *)

(* Finished *)
type finished = bytes