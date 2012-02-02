(* Application data protocol *)

(* We do not support warnings, as there is no good reason to do so *)

module AppData
open Bytes
open Error
open TLSInfo
open AppDataStream

type app_state

val init: ConnectionInfo -> app_state

(*
val reset_incoming: app_state -> app_state
val reset_outgoing: app_state -> app_state
val set_SessionInfo: app_state -> SessionInfo -> app_state
*)

(* Application data to/form application *)

(* Enqueue app data in the output buffer *)
val send_data: ConnectionInfo -> app_state -> lengths -> bytes -> app_state

(* Tells whether the output buffer is empty *)
//val is_outgoing_empty: ConnectionInfo -> app_state -> bool

(* Dequeue app data from the input buffer *)
val retrieve_data: ConnectionInfo -> app_state -> (bytes * app_state)
val is_incoming_empty: ConnectionInfo -> app_state -> bool

(* Application data to/from dispatcher (hence record) *)

(* Dequeue app data from the output buffer *)
val next_fragment: ConnectionInfo -> int -> app_state -> ((int * fragment) * app_state) option
(* Enqueue app data in the input buffer, only called on an empty input buffer *)
val recv_fragment: ConnectionInfo -> int -> app_state -> int -> fragment -> app_state

val reIndex: ConnectionInfo -> ConnectionInfo -> app_state -> app_state
