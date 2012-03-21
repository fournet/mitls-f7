(* Alert protocol *)

module Alert

open Error
open TLSInfo
open AlertPlain

type pre_al_state
type state = pre_al_state

type ALFragReply =
    | EmptyALFrag
    | ALFrag of DataStream.range * fragment
    | LastALFrag of DataStream.range * fragment
    | LastALCloseFrag of DataStream.range * fragment

type alert_reply =
    | ALAck of state
    | ALClose of state
    | ALClose_notify of state

val init: ConnectionInfo -> state

val send_alert: ConnectionInfo -> state -> alertDescription -> state

val next_fragment: ConnectionInfo -> state -> (ALFragReply * state) 

val recv_fragment: ConnectionInfo -> state -> DataStream.range -> fragment -> alert_reply Result

val incomingEmpty: state -> bool
