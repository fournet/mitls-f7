module AppData

open Data
open Record
open Error_handling
open Sessions
open Formats
open Stream

type app_state = {
  app_info: SessionInfo
  app_incoming: stream (* unsolicited data *)
  app_outgoing: stream (* empty_bstr if nothing to be sent *) 
}

let init info =
    {app_info = info;
     app_incoming = new_stream();
     app_outgoing = new_stream()}
  
let send_data (state:app_state) (data:bytes) =
    let new_out = stream_write state.app_outgoing data in
    {state with app_outgoing = new_out}

let retrieve_data (state:app_state) (len:int) :(bytes * app_state) option =
    if is_empty_stream state.app_incoming then
        None
    else
        let (f,rem) = stream_read state.app_incoming len in
        let state = {state with app_incoming = rem}
        let res = (f,state) in
        Some res

let next_fragment state len =
    if is_empty_stream state.app_outgoing then
        None
    else
        let (f,rem) = stream_read state.app_outgoing len in
        let state = {state with app_outgoing = rem}
        let res = (f,state) in
        Some res

let recv_fragment (state:app_state) (fragment:fragment) =
    let new_in = stream_write state.app_incoming fragment in
    correct ({state with app_incoming = new_in})