module AppDataStream

open TLSInfo
open Bytes
open Error

type lengths = int list

type preAppDataStream = {
  history: bytes;
  lengths_history: lengths;
  data: bytes;
  lengths: lengths; 
}
type AppDataStream = preAppDataStream
val emptyAppDataStream: KeyInfo -> AppDataStream
val isEmptyAppDataStream: KeyInfo -> lengths -> AppDataStream -> bool

val writeAppDataStreamBytes: KeyInfo -> lengths -> AppDataStream ->
                bytes -> lengths -> (lengths * AppDataStream)

val readAppDataStreamBytes: KeyInfo -> lengths -> AppDataStream ->
                 (bytes * AppDataStream)

type output_buffer = int * lengths * AppDataStream
type input_buffer = int * lengths * AppDataStream

type app_state = {
  app_incoming: input_buffer;
  app_outgoing: output_buffer;
}

val init: ConnectionInfo -> app_state

type fragment = {b:bytes}

type preds = 
    AppDataFragmentSequence of KeyInfo * int * bytes
  | AppDataFragment of KeyInfo * int * int * bytes
  | NonAppDataSequenceNo of KeyInfo * int
  | AppDataSequenceNo of KeyInfo * int
  | ValidAppDataStream of KeyInfo * bytes


val fragment: KeyInfo -> int -> int -> bytes -> fragment
val repr: KeyInfo -> int -> int -> fragment -> bytes

val writeAppDataBytes: ConnectionInfo -> app_state -> bytes -> lengths -> app_state

val readAppDataBytes: ConnectionInfo -> app_state -> (bytes * app_state)

val readAppDataFragment: ConnectionInfo ->  app_state -> (int * fragment * app_state) option

val readNonAppDataFragment: ConnectionInfo ->  app_state ->  app_state

val writeAppDataFragment: ConnectionInfo ->  app_state -> int -> fragment -> app_state

val writeNonAppDataFragment: ConnectionInfo ->  app_state ->  app_state

val reIndex: ConnectionInfo ->  ConnectionInfo -> app_state -> app_state

val is_incoming_empty: ConnectionInfo ->  app_state -> bool
val is_outgoing_empty: ConnectionInfo ->  app_state -> bool
