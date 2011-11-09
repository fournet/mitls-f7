module Dispatch

open Data
open Formats
open Tcp
open Error_handling
open Record
open Handshake
open TLSInfo
open AppCommon

type preConnection
type Connection = preConnection

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

val writeOneAppFragment: Connection -> Connection Result
val readOneAppFragment: Connection -> int -> ((bytes Result) * Connection)
val appDataAvailable: Connection -> bool

val getSessionInfo: Connection -> SessionInfo

val commit: Connection -> bytes -> Connection
val is_commit_empty: Connection -> bool