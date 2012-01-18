module AppData

open Error
open TLSInfo
open Formats
open AppDataPlain

type pre_app_state = {
  app_in_lengths: lengths
  app_incoming: appdata (* unsolicited data *)
  app_out_lengths: lengths
  app_outgoing: appdata
}

type app_state = pre_app_state

let init si =
    {app_outgoing = empty_appdata si;
     app_out_lengths = [];
     app_incoming = empty_appdata si;
     app_in_lengths = [];}


// internal; only used when the user retrieves data, and so we flush this buffer.
let reset_incoming si app_state =
    {app_state with app_incoming = empty_appdata si; app_in_lengths = []}
(*
let reset_outgoing app_state =
    let si = app_state.app_info
    {app_state with app_outgoing = empty_appdata si; app_out_lengths = []}

let set_SessionInfo app_state sinfo =
    {app_state with app_info = sinfo}
*)

let send_data (state:app_state) si lens (data:appdata) =
    (* TODO: different strategies are possible.
        - Append given data to already committed appdata, and re-schedule lengths
        - Ensure the current appdata is empty before committing to the new one,
           otherwise unexpectedError (and refinement types ensure this never happens)
       Currently we implement the latter *)
    if is_empty_appdata si state.app_outgoing then
        {state with app_outgoing = data; app_out_lengths = lens}
    else
        unexpectedError "[send_data] should be invoked only when previously committed data are over."

let is_outgoing_empty (si:SessionInfo) state =
    is_empty_appdata si state.app_outgoing

let retrieve_data (si:SessionInfo) (state:app_state) =
    let res = state.app_incoming in
    let state = reset_incoming si state in
    (res,state)

let is_incoming_empty (si:SessionInfo) state =
    is_empty_appdata si state.app_incoming

let next_fragment ki state =
    if is_outgoing_empty ki.sinfo state then
        None
    else
        let (newFrag,newAppData) = app_fragment ki state.app_out_lengths state.app_outgoing in
        let (newLengths,newOutgoing) = newAppData in
        let state = {state with app_out_lengths = newLengths; app_outgoing = newOutgoing} in
        Some (newFrag,state)

let recv_fragment ki (state:app_state) (tlen:int) (fragment:fragment) =
    let (newLengths, newAppdata) = concat_fragment_appdata ki tlen fragment state.app_in_lengths state.app_incoming in
    {state with app_in_lengths = newLengths; app_incoming = newAppdata}