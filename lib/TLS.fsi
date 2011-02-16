module TLS

open Data
open Tcp
open Formats
open Error_handling
open Dispatch
open Sessions

(* FIXME: to be handled in handshake? *)
(*type SessionID*)    (* internally storing the mutable state for the session *) 
type ConnectionID (* internally storing the mutable state for the connection *)

type ServerName
type CertName

(* TODO: provide more flexibility for authorization and security queries *)

(* TODO: understand why OpenSSL uses just *ssl both for sessions and connections *)
  
(* client *)
val connect: NetworkStream -> ServerName -> (sessionID * ConnectionID) Result 
val resume: NetworkStream -> sessionID -> (sessionID * ConnectionID) Result
(* the caller compares SessionIDs to understand whether the resumption was accepted or not *)
(* TODO: where do we get cert info in case the resumption is rejectect? *)

(* server *)
val accept: NetworkStream -> CertName -> (sessionID * ConnectionID) Result 

(* basic interface, aligned on the one for TCP *)
val read: ConnectionID -> int -> bytes Result 
val write: ConnectionID -> bytes -> unit Result
val shutdown: ConnectionID -> bool -> unit (* what's this boolean? *)

val close: sessionID -> unit

(* TODO: when receiving an alert, do we terminate the connection and/or the session? *)

(* we establish a fresh session on an existing connection *)
val rehandshake: ServerName -> ConnectionID -> sessionID Result
(* TODO: is it client-side only? *)

(* we resume an existing session on an existing connection *)
val resume_on_connection: sessionID * ConnectionID -> sessionID Result 
