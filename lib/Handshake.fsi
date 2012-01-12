(* Handshake protocol *) 
module Handshake

open Error
//open Formats
//open HS_msg
open CipherSuites
open TLSInfo
open TLSPlain
open TLSKey
open AppCommon
//open SessionDB

// There is one instance of the protocol for each TCP connection,
// each performing a sequence of Handshakes for that connection.

// protocol state  
type pre_hs_state 
type hs_state = pre_hs_state  

(* Locally controlling handshake protocols *) 

//TODO better names, maybe: init/accept resume reshake rekey request

// Create instance for a fresh connection (without resumption) 
val init_handshake: Direction -> protocolOptions -> hs_state

// Create instance for a fresh connection (Client-only, resuming some other sessions)
val resume_handshake: SessionInfo -> PRFs.masterSecret -> protocolOptions -> hs_state

// All other calls are affine in the Handshake protocol state


// Idle client starts a full handshake on the current connection
val start_rehandshake: hs_state -> protocolOptions -> hs_state

// Idle client starts an abbreviated handshake resuming the current session 
val start_rekey:       hs_state -> protocolOptions -> hs_state

// (Idle) Server requests an handshake 
val start_hs_request:  hs_state -> protocolOptions -> hs_state


// ? resetting; TODO we'll try to get rid of it, and ensure that 
// handshake.fs leaves hs_state in the resulting state after completion
val new_session_idle:  hs_state -> SessionInfo -> PRFs.masterSecret -> hs_state


(* Sending Handshake and CCS fragments *)

//TODO make SessionDB internal to handshake (or object!)
//TODO systematically rename FullyFinished to Complete etc
//TODO provide support for indexing fragments (probably by directed si, not ki)

(*
// the new one will be:
type (*(;ki)*) outgoing =
  | OutNone        (* nothing to send *) 
  | OutSome of     int * (*(;ki,l)*) fragment            
  | OutCCS of      int * (*(;ki,l)*) fragment * ccs_data (* the unique one-byte CCS + writing params *)
  | OutFinished of int * (*(;ki,l)*) fragment (* signalling that this fragment ends the finished message *)
  | OutComplete of int * (*(;ki,l)*) fragment (* idem, but also stating the handshake is complete *)
val nextFragment: KeyInfo -> hs_state -> outgoing * hs_state

type (*(;ki)*) incoming = (* the fragment is accepted, and... *)
  | InAck (* nothing happens *)
  | InCheck of ProtocolVersion (* as client, must now check the negotiated version *)
  | InPatch of ProtocolVersion (* as server, must now patch the negotiated version *)
  | InFinished                 (* signalling that we just accepted the finished message *) 
  | InComplete                 (* idem, but also stating the hanshake is complete *)  
val recvFragment: KeyInfo -> hs_state -> int -> fragment -> incoming Result * hs_state
val recvCCS     : KeyInfo -> hs_state -> int -> fragment -> ccs_data Result * hs_state
*)

type HSFragReply =
  | EmptyHSFrag              (* nothing to send *) 
  | HSFrag of                (int * fragment)
  | CCSFrag of               (int * fragment) (* the unique one-byte CCS *) * (KeyInfo * ccs_data)
  | HSWriteSideFinished of   (int * fragment) (* signalling that this fragment ends the finished message *)
  | HSFullyFinished_Write of (int * fragment) * SessionDB.StorableSession
val next_fragment: hs_state -> HSFragReply * hs_state

(* Receiving Handshake and CCS fragments *) 

type recv_reply = (* the fragment is accepted, and... *)
  | HSAck (* nothing happens *)
  | HSVersionAgreed of ProtocolVersion (* use this new protocol version for sending *)
  | HSReadSideFinished (* ? *) 
  | HSFullyFinished_Read of SessionDB.StorableSession (* we can start sending data on the connection *)  
val recv_fragment: hs_state -> int -> fragment -> recv_reply Result * hs_state
val recv_ccs     : hs_state -> int -> fragment -> ((KeyInfo * ccs_data) Result) * hs_state
