(* Application data protocol *)

(* We do not support warnings, as there is no good reason to do so *)

module AppData

open Data
open Record
open Error_handling
open Sessions

type app_state

val init: SessionInfo -> app_state

val send_data: app_state -> bytes -> app_state Result

val next_fragment: app_state -> int -> (fragment * app_state) option

val recv_fragment: app_state -> fragment -> app_state Result 
