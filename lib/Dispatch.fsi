module Dispatch

open Bytes
open Formats
open Tcp
open Error
open Record
open Handshake
open TLSInfo
open DataStream

type Connection

val init: NetworkStream -> Direction -> protocolOptions -> Connection

val resume: NetworkStream -> sessionID -> protocolOptions -> unit Result * Connection

val ask_rehandshake: Connection -> protocolOptions -> Connection
val ask_rekey: Connection -> protocolOptions -> Connection
val ask_hs_request: Connection -> protocolOptions -> Connection

(*
val resume_session: NetworkStream -> SessionInfo -> Connection (* New connection same session *)
val resume_connection: Connection -> Connection (* New crypto same TCP stream same session *)
val renegotiate: Connection -> protocolOptions -> Connection (* New session same TCP stream *)
*)

(* FIXME: unsure we want still to expose those functions to the upper levels *)
(*
val sendNextFragments: Connection -> (unit Result) * Connection
val readNextAppFragment: Connection -> (unit Result) * Connection
*)

val writeAppData: Connection -> (unit Result) * Connection
val readAppData: Connection -> (Connection * ((range * delta) Result))
val readHS: Connection -> (unit Result) * Connection
(* val appDataAvailable: Connection -> bool *)

val getSessionInfo: Connection -> SessionInfo

(* Fills the output buffer with the given data.
   Do not send anything on the network yet. *)
val commit: Connection -> range -> delta -> Connection
(* val write_buffer_empty: Connection -> bool *)

val writeDelta: Connection -> range -> delta -> Connection * ((range * delta) option Result)
val readDelta: Connection -> Connection * ((range * delta) Result)
