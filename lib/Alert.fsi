(* Alert protocol *)

(* We do not support sending warnings, as there is no good reason to do so *)

module Alert
open Data
open Error_handling
open Record
open Sessions

type pre_al_state
type al_state = pre_al_state

type ALFragReply =
    | EmptyALFrag
    | ALFrag of bytes
    | LastALFrag of bytes

type alert_reply =
    | ALAck of al_state
    | ALClose of al_state
    | ALClose_notify of al_state

val init: SessionInfo -> al_state

val send_alert: al_state -> alertDescription -> al_state Result

val next_fragment: al_state -> int -> (ALFragReply * al_state) 

val recv_fragment: al_state -> fragment -> alert_reply Result