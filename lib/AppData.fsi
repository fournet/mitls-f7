(* Application data protocol *)

(* We do not support warnings, as there is no good reason to do so *)

module AppData

open Error
open TLSInfo
open AppDataPlain

type pre_app_state
type app_state = pre_app_state

val init: SessionInfo -> app_state

(*
val reset_incoming: app_state -> app_state
val reset_outgoing: app_state -> app_state
val set_SessionInfo: app_state -> SessionInfo -> app_state
*)

(* Application data to/form application *)

(* Enqueue app data in the output buffer *)
val send_data: app_state -> SessionInfo -> lengths -> appdata -> app_state

(* Tells whether the output buffer is empty *)
val is_outgoing_empty: SessionInfo -> app_state -> bool

(* Dequeue app data from the input buffer *)
val retrieve_data: SessionInfo -> app_state -> (appdata * app_state)
val is_incoming_empty: SessionInfo -> app_state -> bool

(* Application data to/from dispatcher (hence record) *)

(* Dequeue app data from the output buffer *)
val next_fragment: KeyInfo -> app_state -> ((int * fragment) * app_state) option
(* Enqueue app data in the input buffer, only called on an empty input buffer *)
val recv_fragment: KeyInfo -> app_state -> int -> fragment -> app_state
