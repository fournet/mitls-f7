module Alert

open Error
open TLSInfo
open DataStream

type pre_al_state
type state = pre_al_state

type stream = DataStream.stream
type fragment = delta

type ALFragReply =
    | EmptyALFrag
    | ALFrag of range * fragment
    | LastALFrag of range * fragment
    | LastALCloseFrag of range * fragment

type alert_reply =
    | ALAck of state
    | ALClose of state
    | ALClose_notify of state

val init: ConnectionInfo -> state

val send_alert: ConnectionInfo -> state -> alertDescription -> state

val next_fragment: ConnectionInfo -> state -> (ALFragReply * state) 

val recv_fragment: ConnectionInfo -> state -> range -> fragment -> alert_reply Result

val incomingEmpty: state -> bool
