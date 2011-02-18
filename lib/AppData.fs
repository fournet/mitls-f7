module AppData

open Data
open Record
open Error_handling
open Sessions
open Formats
open FIFO

type app_state = {
  app_info: SessionInfo
  app_outgone: Fifo

  app_incoming: Fifo (* unsolicited data *)
  app_outgoing: Fifo (* empty_bstr if nothing to be sent *) 
}

let init info =
    {app_info = info;
     app_outgone = empty_Fifo;
     app_incoming = empty_Fifo;
     app_outgoing = empty_Fifo}
  
let send_data (state:app_state) (data:bytes) =
    let new_out = enqueue_data state.app_outgoing data in
    {state with app_outgoing = new_out}

let retrieve_data (state:app_state) (len:int) :(bytes * app_state) option =
    None
    (*
    if is_empty_Fifo state.app_incoming then
        None
    else
        let (f,rem) = dequeue_data state.app_incoming len in
        let state = {state with app_incoming = rem} in
        let res = (f,state) in
        Some res
    *)


let next_fragment state len =
    if is_empty_Fifo state.app_outgoing then
        None
    else
        let (f,rem) = dequeue_fragment state.app_outgoing len in
        let new_outgone = enqueue_fragment state.app_outgone f in (* GHOST *)
        let state = {state with app_outgoing = rem
                                app_outgone = new_outgone} in (* GHOST *)
        let res = (f,state) in
        Some res

let recv_fragment (state:app_state) (fragment:fragment) =
    correct(state)
    (*
    let new_in = enqueue_fragment state.app_incoming fragment in
    correct ({state with app_incoming = new_in})
    *)
