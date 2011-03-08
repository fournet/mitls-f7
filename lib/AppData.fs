module AppData

open Data
open Record
open Error_handling
open Sessions
open Formats
open Stream

type pre_app_state = {
  app_info: SessionInfo
  app_incoming: stream (* unsolicited data *)
  app_outgoing: stream
}

type app_state = pre_app_state

let init info =
    {app_info = info;
     app_incoming = new_stream Bytearray.empty_bstr;
     app_outgoing = new_stream Bytearray.empty_bstr}

let reset_incoming app_state =
    { app_info = app_state.app_info;
      app_incoming = new_stream Bytearray.empty_bstr;
      app_outgoing = app_state.app_outgoing}

let reset_outgoing app_state =
    { app_info = app_state.app_info;
      app_incoming = app_state.app_incoming;
      app_outgoing = new_stream Bytearray.empty_bstr}

let set_SessionInfo app_state info =
    { app_info = info;
      app_incoming = app_state.app_incoming;
      app_outgoing = app_state.app_outgoing}

let send_data (state:app_state) (data:bytes) =
    let new_out = stream_write state.app_outgoing data in
    {state with app_outgoing = new_out}

let retrieve_data (state:app_state) (len:int) =
    let (f,rem) = stream_read state.app_incoming len in
    let state = {state with app_incoming = rem} in
    let res = (f,state) in
    res

let retrieve_data_available state =
    is_empty_stream state.app_incoming

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
    {state with app_incoming = new_in}