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
    | LastALCloseFrag of (int * fragment)

type alert_reply =
    | ALAck of state
    | ALClose of state
    | ALClose_notify of state

val init: state

val send_alert: state -> alertDescription -> state

val next_fragment: KeyInfo -> state -> (ALFragReply * state) 

val recv_fragment: KeyInfo -> state -> int -> fragment -> alert_reply Result