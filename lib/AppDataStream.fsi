module AppDataStream

open TLSInfo
open Bytes
open Error
open DataStream

type app_state

val inStream:  ConnectionInfo -> app_state -> stream
val outStream: ConnectionInfo -> app_state -> stream

val is_incoming_empty: ConnectionInfo ->  app_state -> bool
val is_outgoing_empty: ConnectionInfo ->  app_state -> bool

val init: ConnectionInfo -> app_state

val writeAppData: ConnectionInfo -> app_state -> range -> delta -> app_state
val emptyOutgoingAppData: ConnectionInfo -> app_state -> ((range * delta) option * app_state)
val next_fragment: ConnectionInfo -> app_state -> (range * Fragment.fragment * app_state) option

val recv_fragment: ConnectionInfo ->  app_state -> range -> Fragment.fragment -> app_state

val readAppData: ConnectionInfo -> app_state -> ((range * delta) option * app_state)

val reset_incoming:  ConnectionInfo -> app_state -> ConnectionInfo -> app_state

val reset_outgoing:  ConnectionInfo -> app_state -> ConnectionInfo -> app_state
