module Alert

open Error
open TLSInfo
open DataStream

type pre_al_state
type state = pre_al_state

type ALFragReply =
    | EmptyALFrag
    | ALFrag of range * Fragment.fragment
    | LastALFrag of range * Fragment.fragment * alertDescription
    | LastALCloseFrag of range * Fragment.fragment

type alert_reply =
    | ALAck of state
    | ALFatal of alertDescription * state
    | ALWarning of alertDescription * state
    | ALClose_notify of state

val init: ConnectionInfo -> state

val send_alert: ConnectionInfo -> state -> alertDescription -> state

val next_fragment: ConnectionInfo -> state -> (ALFragReply * state) 

val recv_fragment: ConnectionInfo -> state -> range -> Fragment.fragment -> alert_reply Result

val incomingEmpty: ConnectionInfo -> state -> bool
