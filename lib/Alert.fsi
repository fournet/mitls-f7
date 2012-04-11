module Alert

open Error
open TLSInfo
open DataStream

type pre_al_state
type state = pre_al_state

type ALFragReply =
    | EmptyALFrag
    | ALFrag of range * delta
    | LastALFrag of range * delta
    | LastALCloseFrag of range * delta

type alert_reply =
    | ALAck of state
    | ALClose of state
    | ALClose_notify of state

val init: ConnectionInfo -> state

val send_alert: ConnectionInfo -> state -> alertDescription -> state

val next_fragment: ConnectionInfo -> state -> (ALFragReply * state) 

val recv_fragment: ConnectionInfo -> state -> range -> delta -> alert_reply Result

val incomingEmpty: state -> bool
