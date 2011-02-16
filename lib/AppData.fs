module AppData

open Data
open Record
open Error_handling
open Sessions
open Formats

type app_state = {
  app_info: SessionInfo
  app_outgone: bytes
  app_out_fragno: int

  app_incoming: bytes (* unsolicited data *)
  app_outgoing: bytes (* empty_bstr if nothing to be sent *) 
}

let init info =
    {app_info = info;
     app_outgone = empty_bstr;
     app_out_fragno = 0;
     app_incoming = empty_bstr;
     app_outgoing = empty_bstr}
  
let send_data (state:app_state) (data:bytes) =
    let new_out = append state.app_outgoing data in
    {state with app_outgoing = new_out}

let retrieve_data (state:app_state) (len:int) :(bytes * app_state) option =
    None
    (*
    if equalBytes state.app_incoming empty_bstr then
        None
    else
        let (f,rem) = split state.app_incoming len in
        let state = {state with app_incoming = rem} in
        let res = (f,state) in
        Some res
    *)


let next_fragment state len =
    if equalBytes state.app_outgoing empty_bstr then
        None
    else
        let (f,rem) = split state.app_outgoing len in
        let new_fragno = state.app_out_fragno + 1 in (* GHOST *)
        let new_outgone = append state.app_outgone f in (* GHOST *)
        let state = {state with app_outgoing = rem
                                app_out_fragno = new_fragno (* GHOST *)
                                app_outgone = new_outgone} in (* GHOST *)
        let res = (f,state) in
        Some res

let recv_fragment (state:app_state) (fragment:fragment) =
    correct(state)
    (*
    let new_in = append state.app_incoming fragment in
    correct ({state with app_incoming = new_in})
    *)
