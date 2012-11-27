module Alert

open Error
open TLSInfo
open DataStream

type pre_al_state
type state = pre_al_state

type ALFragReply =
    | EmptyALFrag
    | ALFrag of range * HSFragment.fragment
    | LastALFrag of range * HSFragment.fragment * alertDescription
    | LastALCloseFrag of range * HSFragment.fragment

type alert_reply =
    | ALAck of state
    | ALFatal of alertDescription * state
    | ALWarning of alertDescription * state
    | ALClose_notify of state

val alertBytes: alertDescription -> Bytes.bytes

val init: ConnectionInfo -> state

val send_alert: ConnectionInfo -> state -> alertDescription -> state

val next_fragment: ConnectionInfo -> state -> (ALFragReply * state) 

val recv_fragment: ConnectionInfo -> state -> range -> HSFragment.fragment -> alert_reply Result

val reset_incoming: ConnectionInfo -> state -> ConnectionInfo -> state
val reset_outgoing: ConnectionInfo -> state -> ConnectionInfo -> state

