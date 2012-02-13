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

val init: ConnectionInfo -> app_state

type fragment = delta

type preds = 
    AppDataFragmentSequence of KeyInfo * int * bytes
  | AppDataFragment of KeyInfo * int * int * bytes
  | NonAppDataSequenceNo of KeyInfo * int
  | AppDataSequenceNo of KeyInfo * int
  | ValidAppDataStream of KeyInfo * bytes

val writeAppData: ConnectionInfo -> app_state -> range -> delta -> app_state
val readAppData: ConnectionInfo -> app_state -> ((range * delta) option * app_state)

val readAppDataFragment: ConnectionInfo ->  app_state -> (range * fragment * app_state) option

val readNonAppDataFragment: ConnectionInfo ->  app_state ->  app_state

val writeAppDataFragment: ConnectionInfo ->  app_state -> range -> fragment -> app_state

val writeNonAppDataFragment: ConnectionInfo ->  app_state ->  app_state

val reIndex: ConnectionInfo ->  ConnectionInfo -> app_state -> app_state

val reset_incoming:  ConnectionInfo -> app_state -> app_state

val reset_outgoing:  ConnectionInfo -> app_state -> app_state

val is_incoming_empty: ConnectionInfo ->  app_state -> bool
val is_outgoing_empty: ConnectionInfo ->  app_state -> bool

val repr: KeyInfo -> int -> int -> fragment -> bytes
val fragment: KeyInfo -> int -> int -> bytes -> fragment 
