module AppData

open Data
open Record
open Error_handling
open Sessions
open Formats

type app_state = {
  app_info: SessionInfo
  app_incoming: bytes (* unsolicited data *)
  app_outgoing: bytes (* empty_bstr if nothing to be sent *) 
  (* we are still unsure what to do when we CCS with incoming/outgoing data *)
}

let init info = {app_info = info ; app_incoming = empty_bstr; app_outgoing = empty_bstr}
  
let send_data (state:app_state) (data:bytes) =
    correct (state)

let next_fragment state len =
    if equalBytes state.app_outgoing empty_bstr then
        None
    else
        let (f,rem) = split state.app_outgoing len in
        let state = {state with app_outgoing = rem} in
        let res = (f,state) in
        Some res

let recv_fragment (state:app_state) (fragment:fragment) =
    correct (state)
