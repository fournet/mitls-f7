module Dispatch

open Data
open Formats
open Tcp
open Error_handling
open Record
open Handshake
open Sessions

type Connection

val init: NetworkStream -> role -> protocolOptions -> Connection

(*
val resume_session: NetworkStream -> SessionInfo -> Connection (* New connection same session *)
val resume_connection: Connection -> Connection (* New crypto same TCP stream same session *)
val renegotiate: Connection -> protocolOptions -> Connection (* New session same TCP stream *)
*)

val sendNextFragments: Connection -> Connection Result
val readNextAppFragment: Connection -> Connection Result

(*
// older:
type CallbackType =
    | Handshake_and_Change_Cihper_Spec
    | Alert
    | Application_Data

type RecordMessage =
    | NoMsg
    | SomeMsg of (ContentType * bytes)

val init: NetworkStream -> ProtocolVersionType -> Dispatcher

val registerPollCallback: Dispatcher -> CallbackType -> (Dispatcher -> (Dispatcher * RecordMessage) ) -> Dispatcher
val registerDispatchCallback: Dispatcher -> CallbackType -> (Dispatcher -> RecordMessage -> Dispatcher) -> Dispatcher

val null_poll_cb: Dispatcher -> (Dispatcher * RecordMessage)
val null_dispatch_cb: Dispatcher -> RecordMessage -> Dispatcher

val runLoop: Dispatcher -> DispatcherState

(* The following functions break the abstraction between record layer and upper
   protocols, as implicitly required by the RFC *)

val setHandshakeVersion: Dispatcher -> ProtocolVersionType -> Dispatcher
(* More to come, e.g. functions to set session keys *)
*)
