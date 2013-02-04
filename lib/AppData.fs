module AppData

open Error
open Bytes
open TLSInfo
open DataStream
open Range

type input_buffer =  stream * (range * AppFragment.fragment) option
type output_buffer = stream * (range * delta) option

type app_state = {
  app_incoming: input_buffer;
  app_outgoing: output_buffer;
}

let inStream  (c:ConnectionInfo) state = 
    let (s,_) = state.app_incoming in s
let outStream (c:ConnectionInfo) state =
    let (s,_) = state.app_outgoing in s

let init ci =
  let in_s = DataStream.init ci.id_in in
  let out_s = DataStream.init ci.id_out in
    {app_outgoing = (out_s,None);
     app_incoming = (in_s,None)
    }

// Stores appdata in the output buffer, so that it will possibly sent on the network
let writeAppData (c:ConnectionInfo) (a:app_state) (r:range) (d:delta) =
    // pre: snd a.app_outgoing = None
    let (s,_) = a.app_outgoing in
    let nd = (r,d) in
    {a with app_outgoing = (s,Some(nd))}

// When polled, gives the Dispatch the next fragment to be delivered,
// and commits to it (adds it to the output stream)
let next_fragment (c:ConnectionInfo) (a:app_state) =
    let (s,data) = a.app_outgoing in
    match data with
      | None -> None
      | Some (rd) ->
        let (r,d) = rd in
        let f0,ns = AppFragment.fragment c.id_out s r d in
        let state = {a with app_outgoing = (ns,None)} in
        let res = (r,f0,state) in
        Some(res)

// Clear contents from the output buffer
let clearOutBuf (c:ConnectionInfo) (a:app_state) =
    let (s,data) = a.app_outgoing in
    {a with app_outgoing = (s,None)}

// Gets a fragment from Dispatch, adds it to the incoming buffer, but not yet to
// the stream of data delivered to the user
let recv_fragment (ci:ConnectionInfo)  (a:app_state)  (r:range) (f:AppFragment.fragment) =
    // pre: snd a.app_incoming = None
    let (s,_) = a.app_incoming in
    let rf = (r,f) in
    {a with app_incoming = (s,Some(rf))}

// Returns the buffered data to the user, and stores them in the stream
let readAppData (c:ConnectionInfo) (a:app_state) =
  let (s,data) = a.app_incoming in
    match data with
      | None -> None,a
      | Some(rf) ->
          let (r,f) = rf in
          let (d,ns) = AppFragment.delta c.id_in s r f in
          let rd = (r,d) in
          Some(rd),{a with app_incoming = (ns,None)}


let reset_outgoing (ci:ConnectionInfo) (a:app_state) (nci:ConnectionInfo) = 
  let out_s = DataStream.init nci.id_out in
    {a with 
       app_outgoing = (out_s,None)
    }

let reset_incoming (ci:ConnectionInfo) (a:app_state) (nci:ConnectionInfo) = 
  let in_s = DataStream.init nci.id_in in
    {a with 
       app_incoming =  (in_s,None)
    }
