(* Alert protocol *)

module Alert

open Error
open TLSInfo

type pre_al_state
type state = pre_al_state

// protocol-specific abstract fragment,
// and associated functions (never to be called with ideal functionality)
type fragment
val repr: KeyInfo -> int -> fragment -> Bytes.bytes
val fragment: KeyInfo -> Bytes.bytes -> ((int * fragment) * Bytes.bytes)

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