module Record

open Bytes
open Tcp
open TLSConstants
open Error
open TLSInfo
open Range


/// Implements stateful AE on top of LHAE,
/// managing sequence numbers and the binary record format

type ConnectionState
type sendState = ConnectionState
type recvState = ConnectionState

val initConnState: epoch -> StatefulLHAE.rw -> StatefulLHAE.state -> ConnectionState
val nullConnState: epoch -> StatefulLHAE.rw -> ConnectionState

//val parseHeader: bytes -> (ContentType * ProtocolVersion * int) Result

val headerLength: bytes -> int Result

// CF do some uniform renaming, e.g. s/Out/Send/
val recordPacketOut: epoch -> sendState -> ProtocolVersion -> range -> ContentType -> TLSFragment.fragment -> (sendState * bytes)
val recordPacketIn : epoch -> recvState -> bytes -> (recvState * ContentType * ProtocolVersion * range * TLSFragment.fragment) Result

val history: epoch -> StatefulLHAE.rw -> ConnectionState -> TLSFragment.history

// val historyStream: epoch -> ConnectionState -> ContentType -> DataStream.stream

(* val dataAvailable: recvState -> bool Result *)
(* val coherentrw: SessionInfo -> recvState -> sendState -> bool *)

(* ProtocolVersion: 
  - the interface can be used only for setting and checking them (they are never passed up)
  - initially, sendState is the minimal and recvState is Unknown. 
  - for receiving only, the "Unknown" ProtocolVersion means that we do not know yet, 
    so we are accepting any reasonable one in each record.
    Conservatively, we change from Unknown to the first received version. *)

(* for now, we do not provide an interface for reporting sequence number overflows *)

 
