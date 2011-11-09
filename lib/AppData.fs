module AppData

open Data
open Record
open Error_handling
open TLSInfo
open TLSPlain
open Formats

type pre_app_state = {
  app_info: SessionInfo
  role: Direction
  app_in_lengths: Lengths
  app_incoming: appdata (* unsolicited data *)
  app_out_lengths: Lengths
  app_outgoing: appdata
}

type app_state = pre_app_state

let init sinfo role =
    {app_info = sinfo;
     role = role;
     app_outgoing = empty_appdata;
     app_out_lengths = empty_lengths;
     app_incoming = empty_appdata;
     app_in_lengths = empty_lengths;}

let reset_incoming app_state =
    {app_state with app_incoming = empty_appdata; app_in_lengths = empty_lengths}

let reset_outgoing app_state =
    {app_state with app_outgoing = empty_appdata; app_out_lengths = empty_lengths}

let set_SessionInfo app_state sinfo =
    {app_state with app_info = sinfo}

let send_data (state:app_state) (data:bytes) =
    (* TODO: different strategies are possible.
        - Append given data to already committed appdata, and re-schedule lengths
        - Ensure the current appdata is empty before committing to the new one,
           otherwise unexpectedError (and refinement types ensure this never happens)
       Currently we implement the latter *)
    if is_empty_appdata state.app_outgoing then
        let lengths = estimateLengths state.app_info (Bytearray.length data) in
        let new_out = appdata state.app_info lengths data in
        {state with app_outgoing = new_out; app_out_lengths = lengths}
    else
        unexpectedError "[send_data] should be invoked only when previously committed data are over."

let is_outgoing_empty state =
    is_empty_appdata state.app_outgoing

let retrieve_data (state:app_state) =
    let res = get_bytes state.app_incoming in
    let state = reset_incoming state in
    (res,state)

(*
let retrieve_data_available state =
    not (is_empty_appdata state.app_incoming)
*)

let next_fragment state =
    if is_outgoing_empty state then
        None
    else
        let (newFrag,newAppData) = app_fragment state.app_info state.app_out_lengths state.app_outgoing in
        let (newLengths,newOutgoing) = newAppData in
        let state = {state with app_out_lengths = newLengths; app_outgoing = newOutgoing} in
        Some (newFrag,state)

let recv_fragment (state:app_state) (tlen:int) (fragment:fragment) =
    let (newLengths, newAppdata) = concat_fragment_appdata state.app_info tlen fragment state.app_in_lengths state.app_incoming in
    {state with app_in_lengths = newLengths; app_incoming = newAppdata}