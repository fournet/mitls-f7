module AppDataStream

open TLSInfo
open Bytes
open Error
open DataStream

type app_state
(* = {
  app_incoming: input_buffer;
  app_outgoing: output_buffer;
}*)

val inStream:  ConnectionInfo -> app_state -> stream
val outStream: ConnectionInfo -> app_state -> stream

val init: ConnectionInfo -> app_state

// Used by top level application
// AP: The delta and range given here might not fit in one fragment.
// It's a bit confusing to use delta for things that might not fit in
// one fragment (here), and things that do fit (read/writeAppDataFragment)

// After all, we're sort of buffering user data here (and we unbuffer them before returning in Dispatch).
// We should not buffer any data, and ask the user one fragment at a time. That would help, wouldn't it?
val writeAppData: ConnectionInfo -> app_state -> range -> delta -> app_state
val readAppData: ConnectionInfo -> app_state -> ((range * delta) option * app_state)
val emptyOutgoingAppData: ConnectionInfo -> app_state -> ((range * delta) option * app_state)

// Used internally
val readAppDataFragment: ConnectionInfo ->  app_state -> (range * Fragment.fragment * app_state) option

//val readNonAppDataFragment: ConnectionInfo ->  app_state ->  app_state

val writeAppDataFragment: ConnectionInfo ->  app_state -> range -> Fragment.fragment -> app_state

//val writeNonAppDataFragment: ConnectionInfo ->  app_state ->  app_state

val reset_incoming:  ConnectionInfo -> app_state -> app_state

val reset_outgoing:  ConnectionInfo -> app_state -> app_state

val is_incoming_empty: ConnectionInfo ->  app_state -> bool
val is_outgoing_empty: ConnectionInfo ->  app_state -> bool

val repr: KeyInfo -> stream ->  range -> delta -> bytes
val fragment: KeyInfo -> stream -> range -> bytes -> delta
