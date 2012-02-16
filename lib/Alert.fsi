(* Alert protocol *)

module Alert

open Error
open TLSInfo

type pre_al_state
type state = pre_al_state

// protocol-specific abstract fragment,
// and associated functions (never to be called with ideal functionality)
type fragment
type stream
val addFragment: KeyInfo -> stream -> DataStream.range -> fragment -> stream

val repr: KeyInfo -> stream -> DataStream.range  -> fragment -> Bytes.bytes
val fragment: KeyInfo -> stream -> DataStream.range  -> Bytes.bytes -> fragment

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

val reIndex: ConnectionInfo -> ConnectionInfo -> state -> state

val emptyStream: KeyInfo -> stream
