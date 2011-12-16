(* Alert protocol *)

module Alert

open Bytes
open Error
open TLSPlain
open TLSInfo

type pre_al_state
type state = pre_al_state

type ALFragReply =
    | EmptyALFrag
    | ALFrag of (int * fragment)
    | LastALFrag of (int * fragment)

type alert_reply =
    | ALAck of state
    | ALClose of state
    | ALClose_notify of state

val init: SessionInfo -> state

val send_alert: state -> alertDescription -> state Result

val next_fragment: state -> (ALFragReply * state) 

val recv_fragment: state -> int -> fragment -> alert_reply Result