module AppData

open Bytes
open Error
open TLSInfo
open Formats
open AppDataStream

type buffer = int * lengths * AppDataStream
type app_state = {
  app_incoming: buffer (* unsolicited data *);
  app_outgoing: buffer;
}

let init ci =
    {app_outgoing = (0,[],emptyAppDataStream ci.id_out.sinfo);
     app_incoming = (0,[],emptyAppDataStream ci.id_in.sinfo);
    }

// internal; only used when the user retrieves data, and so we flush this buffer.
let reset_incoming ci app_state =
    {app_state with 
       app_incoming = (0,[],emptyAppDataStream ci.id_in.sinfo);
    }
(*
let reset_outgoing app_state =
    let si = app_state.app_info
    {app_state with app_outgoing = empty_appdata si; app_out_lengths = []}

let set_SessionInfo app_state sinfo =
    {app_state with app_info = sinfo}
*)

let send_data ci (state:app_state) lens (data:bytes) =
    (* TODO: different strategies are possible.
        - Append given data to already committed appdata, and re-schedule lengths
        - Ensure the current appdata is empty before committing to the new one,
           otherwise unexpectedError (and refinement types ensure this never happens)
       Currently we implement the latter *)
  let si = ci.id_out.sinfo in
  let (seqn,ls,ads) = state.app_outgoing in
    if isEmptyAppDataStream si seqn ls ads then
      let (nls,nads) = writeAppDataBytes si seqn ls ads data lens  in
        {state with app_outgoing = (seqn,nls,nads)}
    else
        unexpectedError "[send_data] should be invoked only when previously committed data are over."

let is_outgoing_empty (ci:ConnectionInfo) state =
  let (seqn,ls,ads) = state.app_outgoing in 
    isEmptyAppDataStream ci.id_out.sinfo seqn ls ads

let retrieve_data (ci:ConnectionInfo) (state:app_state) =
  let (seqn,ls,ads) = state.app_incoming in
  let (d,nads) = readAppDataBytes ci.id_in.sinfo seqn ls ads in
  let ns = {state with app_incoming = (seqn,ls,nads)} in
    (d,ns)

let is_incoming_empty (ci:ConnectionInfo) state =
  let (seqn,ls,ads) = state.app_incoming in 
    isEmptyAppDataStream ci.id_in.sinfo seqn ls ads

let next_fragment ci nseqn state =
    if is_outgoing_empty ci state then
        None
    else
      let (seqn,ls,ads) = state.app_outgoing in
      let (tlen,frag,nads) = readAppDataFragment ci.id_out seqn ls ads nseqn in
      let state = {state with app_outgoing = (nseqn,ls,nads)} in
        Some ((tlen,frag),state)

let recv_fragment ci (nseqn:int) (state:app_state) (tlen:int) (fragment:fragment) =
  let (seqn,ls,ads) = state.app_incoming in
  let (nls,nads) = writeAppDataFragment ci.id_in seqn ls ads nseqn tlen fragment in
    {state with app_incoming = (nseqn,nls,nads)}

let reIndex (oldCI:ConnectionInfo) (newCI:ConnectionInfo) (state:app_state) =
    let oldInSI  = oldCI.id_in.sinfo in
    let newInSI  = newCI.id_in.sinfo in
    let oldOutSI = oldCI.id_out.sinfo in
    let newOutSI = newCI.id_out.sinfo in
    let (seqn_in,ls_in,ads_in) = state.app_incoming in
    let (seqn_out,ls_out,ads_out) = state.app_outgoing in
    let nads_in = AppDataStream.reIndex oldInSI newInSI seqn_in ls_in ads_in in
    let nads_out = AppDataStream.reIndex oldOutSI newOutSI seqn_out ls_out ads_out in

    { app_incoming    = (seqn_in,ls_in,nads_in);
      app_outgoing    = (seqn_out,ls_out,nads_out);}
