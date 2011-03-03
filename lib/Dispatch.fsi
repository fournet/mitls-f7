module Dispatch

open Data
open Formats
open Tcp
open Error_handling
open Record
open Handshake
open Sessions
open AppCommon

type Connection

val init: NetworkStream -> role -> protocolOptions -> Connection

(*
val resume_session: NetworkStream -> SessionInfo -> Connection (* New connection same session *)
val resume_connection: Connection -> Connection (* New crypto same TCP stream same session *)
val renegotiate: Connection -> protocolOptions -> Connection (* New session same TCP stream *)
*)

(* FIXME: unsure we want still to expose those functions to the upper levels *)
val sendNextFragments: Connection -> (unit Result) * Connection
val readNextAppFragment: Connection -> (unit Result) * Connection

val writeOneAppFragment: Connection -> bytes -> (((bytes * bytes) Result) * Connection)
val readOneAppFragment: Connection -> int -> ((bytes Result) * Connection)
val appDataAvailable: Connection -> bool

val getSessionInfo: Connection -> SessionInfo