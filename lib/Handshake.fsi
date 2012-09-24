(* Handshake protocol *) 
module Handshake

open Error
open CipherSuites
open TLSInfo
open DataStream

// protocol state  
type pre_hs_state 
type hs_state = pre_hs_state
type nextState = hs_state

(* Control Interface *)
// Create instance for a fresh connection (without resumption) 
val init: Role -> config -> (ConnectionInfo * hs_state)

// Create instance for a fresh connection (Client-only, resuming some other sessions)
val resume: sessionID -> config -> (ConnectionInfo * hs_state)

// Idle client starts a full handshake on the current connection
val rehandshake: ConnectionInfo -> hs_state -> config -> bool * hs_state

// Idle client starts an abbreviated handshake resuming the current session 
val rekey:       ConnectionInfo -> hs_state -> config -> bool * hs_state

// (Idle) Server requests an handshake 
val request:  ConnectionInfo -> hs_state -> config -> bool * hs_state

val authorize: ConnectionInfo -> hs_state -> HSK.cert -> hs_state

val invalidateSession: ConnectionInfo -> hs_state -> hs_state

(* Network Interface *)

[<NoEquality;NoComparison>]
type outgoing =
  | OutIdle of hs_state
  | OutSome of DataStream.range * Fragment.fragment * hs_state
  | OutCCS of  DataStream.range * Fragment.fragment (* the unique one-byte CCS *) *
               ConnectionInfo * StatefulAEAD.state * hs_state
  | OutFinished of DataStream.range * Fragment.fragment * hs_state
  | OutComplete of DataStream.range * Fragment.fragment * hs_state
val next_fragment: ConnectionInfo  -> hs_state -> outgoing

(* Receiving Handshake and CCS fragments *) 

[<NoEquality;NoComparison>]
type incoming = (* the fragment is accepted, and... *)
  | InAck of hs_state
  | InVersionAgreed of hs_state
  | InQuery of HSK.cert * hs_state
  | InFinished of hs_state
  | InComplete of hs_state
  | InError of ErrorCause * ErrorKind * hs_state
val recv_fragment: ConnectionInfo -> hs_state -> DataStream.range -> Fragment.fragment -> incoming

[<NoEquality;NoComparison>]
type incomingCCS =
  | InCCSAck of ConnectionInfo * StatefulAEAD.state * hs_state
  | InCCSError of ErrorCause * ErrorKind * hs_state
val recv_ccs     : ConnectionInfo -> hs_state -> DataStream.range -> Fragment.fragment -> incomingCCS

// Which protocol version dispatch should use to check during the first handshake
val getNegotiatedVersion: ConnectionInfo -> hs_state -> ProtocolVersion
val getMinVersion: ConnectionInfo -> hs_state -> ProtocolVersion
