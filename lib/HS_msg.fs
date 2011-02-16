module HS_msg

open Data
open Bytearray
open Formats
open Record
open HS_ciphersuites
open Sessions

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

let bytes_of_hs_type handshakeType =
    match handshakeType with
    | HT_hello_request -> bytes_of_int 1 0
    | HT_client_hello -> bytes_of_int 1 1
    | HT_server_hello -> bytes_of_int 1 2
    | HT_certificate -> bytes_of_int 1 11
    | HT_server_key_exchange -> bytes_of_int 1 12
    | HT_certificate_request -> bytes_of_int 1 13
    | HT_server_hello_done -> bytes_of_int 1 14
    | HT_certificate_verify -> bytes_of_int 1 15
    | HT_client_key_exchange -> bytes_of_int 1 16
    | HT_finished -> bytes_of_int 1 20
    | HT_unknown x -> failwith "Unkown handhsake type"

let hs_type_of_bytes b =
    let i = int_of_bytes 1 b in
    match i with
    | 0 -> HT_hello_request
    | 1 -> HT_client_hello
    | 2 -> HT_server_hello
    | 11 -> HT_certificate
    | 12 -> HT_server_key_exchange
    | 13 -> HT_certificate_request
    | 14 -> HT_server_hello_done
    | 15 -> HT_certificate_verify
    | 16 -> HT_client_key_exchange
    | 20 -> HT_finished
    | x -> HT_unknown (x)

(* Message bodies *)

(* Hello Request *)
type helloRequest = bytes (* empty bitstring *)

(* Client Hello *)
type hrandom = {time : int; rnd : bytes}
type cipherSuites = CipherSuite list

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

type ASN1Cert = bytes
type certificate = { certificate_list: ASN1Cert }

(* Server Key Exchange *)
(* TODO *)

(* Certificate Request *)
(* TODO *)

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