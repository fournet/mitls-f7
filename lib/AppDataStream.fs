module AppDataStream

open Error
open Bytes
open TLSInfo
open DataStream

type input_buffer =  stream * (range * Fragment.fragment) option
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

// Returns the unsent data to the user, and resets the output buffer
let emptyOutgoingAppData (c:ConnectionInfo) (a:app_state) = 
  let (s,b) = a.app_outgoing in
    match b with
      | None -> None,a
      | Some(nd) -> 
          Some(nd),{a with app_outgoing = (s,None)}

// When polled, gives the Dispatch the next fragment to be delivered,
// and commits to it (adds it to the output stream)
let next_fragment (c:ConnectionInfo) (a:app_state) =
    let (s,data) = a.app_outgoing in
    match data with
      | None -> None
      | Some (rd) ->
          let (r,d) = rd in
          let (r0,r1) = splitRange c.id_out r in
          if r = r0 then
            let f0,ns = Fragment.fragment c.id_out s r d in
            let state = {a with app_outgoing = (ns,None)} in
            let res = (r,f0,state) in
            Some(res)
          else 
            let (d0,d1) = DataStream.split c.id_out s r0 r1 d in
            let f0,ns = Fragment.fragment c.id_out s r0 d0 in
            let nd1 = (r1,d1) in
            let state = {a with app_outgoing = (ns,Some(nd1))} in
            let res = (r0,f0,state) in
            Some(res)

// Gets a fragment from Dispatch, adds it to the incoming buffer, but not yet to
// the stream of data delivered to the user
let recv_fragment (ci:ConnectionInfo)  (a:app_state)  (r:range) (f:Fragment.fragment) =
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
          let (d,ns) = Fragment.delta c.id_in s r f in
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
