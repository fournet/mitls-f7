(* Handshake protocol *) 
module Handshake

open Data
open Record
open Error_handling
open Formats
open HS_msg
open HS_ciphersuites
open TLSInfo
open TLSPlain
open AppCommon

type protoState

type pre_hs_state
type hs_state = pre_hs_state

val init_handshake: SessionInfo -> role -> protocolOptions -> hs_state

(* Only client side *)
val resume_handshake: sessionID -> protocolOptions -> (SessionInfo * hs_state)

val start_rehandshake: hs_state -> protocolOptions -> hs_state
val start_rekey: hs_state -> protocolOptions -> hs_state
val start_hs_request: hs_state -> protocolOptions -> hs_state

val new_session_idle: hs_state -> SessionInfo -> hs_state

(*
val rehandshake: hs_state -> hs_state Result (* new handshake on same connection *)
val rekey: hs_state -> hs_state Result (* resume on same connection *)
val resume: SessionInfo -> hs_state (* resume on different connection; only client-side *)
*)

type HSFragReply =
  | EmptyHSFrag
  | HSFrag of (int * fragment)
  | HSWriteSideFinished of (int * fragment)
  | HSFullyFinished_Write of (int * fragment) * SessionInfo
  | CCSFrag of (int * fragment) * ccs_data

val next_fragment: hs_state -> (HSFragReply * hs_state)

type recv_reply = 
  | HSAck      (* fragment accepted, no visible effect so far *)
  | HSChangeVersion of role * ProtocolVersionType 
                          (* ..., and we should use this new protocol version for sending *) 
  | HSReadSideFinished
  | HSFullyFinished_Read of SessionInfo (* ..., and we can start sending data on the connection *)

(*type hs_output_reply = 
  | HS_Fragment of bytes
  | HS_CCS of ccs_data (* new ccs data *)
  | Idle*)

val recv_fragment: hs_state -> fragment -> (recv_reply Result) * hs_state
val recv_ccs: hs_state -> fragment -> (ccs_data Result) * hs_state