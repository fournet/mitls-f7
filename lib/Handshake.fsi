(* Handshake protocol *) 
module Handshake

open Error
open CipherSuites
open TLSInfo
open DataStream

// protocol state  
type pre_hs_state 
type hs_state = pre_hs_state

(* Control Interface *)
// Create instance for a fresh connection (without resumption) 
val init: Role -> config -> (ConnectionInfo * hs_state)

// Create instance for a fresh connection (Client-only, resuming some other sessions)
// FIXME: Mismatch: handle masterSecret
val resume: SessionInfo -> PRFs.masterSecret -> config -> (ConnectionInfo * hs_state)

// Idle client starts a full handshake on the current connection
val rehandshake: ConnectionInfo -> hs_state -> config -> hs_state

// Idle client starts an abbreviated handshake resuming the current session 
val rekey:       ConnectionInfo -> hs_state -> config -> hs_state

// (Idle) Server requests an handshake 
val request:  ConnectionInfo -> hs_state -> config -> hs_state

val authorize: ConnectionInfo -> hs_state -> Certificate.cert -> hs_state

(* Network Interface *)

type HSFragReply =
  | EmptyHSFrag              (* nothing to send *) 
  | HSFrag of                DataStream.range * Fragment.fragment
  | CCSFrag of               (DataStream.range * Fragment.fragment) (* the unique one-byte CCS *) * (epoch * Record.ConnectionState)
  | HSWriteSideFinished of   DataStream.range * Fragment.fragment (* signalling that this fragment ends the finished message *)
  | HSFullyFinished_Write of (DataStream.range * Fragment.fragment) * SessionDB.StorableSession
val next_fragment: ConnectionInfo  -> hs_state -> HSFragReply * hs_state

(* Receiving Handshake and CCS fragments *) 

type recv_reply = (* the fragment is accepted, and... *)
  | HSAck (* nothing happens *)
  | HSVersionAgreed (* If in first handhsake, ask HS for which protocol version to check and send data *)
  | HSQuery of Certificate.cert
  | HSReadSideFinished
  | HSFullyFinished_Read of SessionDB.StorableSession (* we can start sending data on the connection *)  
val recv_fragment: ConnectionInfo -> hs_state -> DataStream.range -> Fragment.fragment -> recv_reply Result * hs_state
val recv_ccs     : ConnectionInfo -> hs_state -> DataStream.range -> Fragment.fragment -> ((epoch * Record.ConnectionState) Result) * hs_state

// Which protocol version dispatch should use to check during the first handshake
val getNegotiatedVersion: ConnectionInfo -> hs_state -> ProtocolVersion

val reset_incoming: ConnectionInfo -> hs_state -> ConnectionInfo -> hs_state
val reset_outgoing: ConnectionInfo -> hs_state -> ConnectionInfo -> hs_state
