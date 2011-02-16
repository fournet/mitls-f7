(* Handshake protocol *) 
module Handshake

open Data
open Record
open Error_handling
open Formats
open HS_msg
open Sessions

(* We may be sending either HS messages, or a CCS message, 
   but not both at the same time (really?) *)

type output_state = 
  | SendCCS 
  | SendHS of bytes 

type protoState

type protocolOptions = {
    minVer: ProtocolVersionType
    maxVer: ProtocolVersionType
    ciphersuites: cipherSuites
    compressions: Compression list
    }

val defaultProtocolOptions: protocolOptions

type hs_state

val init_handshake: SessionInfo -> protocolOptions -> hs_state
(*
val rehandshake: hs_state -> hs_state Result (* new handshake on same connection *)
val rekey: hs_state -> hs_state Result (* resume on same connection *)
val resume: SessionInfo -> hs_state (* resume on different connection; only client-side *)
*)

type HSFragReply =
  | EmptyHSFrag
  | HSFrag of bytes
  | LastHSFrag of bytes (* Useful to let the dispatcher switch to the Open state *)
  | CCSFrag of bytes * ccs_data

val next_fragment: hs_state -> int -> (HSFragReply * hs_state)

type recv_reply = 
  | HSAck of hs_state      (* fragment accepted, no visible effect so far *)
  | HSChangeVersion of hs_state * role * ProtocolVersionType 
                          (* ..., and we should use this new protocol version for sending *) 
  | HSFinished of hs_state (* ..., and we can start sending data on the connection *)

(*type hs_output_reply = 
  | HS_Fragment of bytes
  | HS_CCS of ccs_data (* new ccs data *)
  | Idle*)

val recv_fragment: hs_state -> fragment -> recv_reply Result
val recv_ccs: hs_state -> fragment -> (hs_state * ccs_data) Result