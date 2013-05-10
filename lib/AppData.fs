module AppData

open Error
open TLSError
open Bytes
open TLSInfo
open DataStream
open Range

type input_buffer =
    | NoneIBuf of stream
    | SomeIBuf of stream * range * AppFragment.plain
type output_buffer =
    | NoneOBuf of stream
    | SomeOBuf of stream * range * AppFragment.plain * stream

type app_state = {
  app_incoming: input_buffer;
  app_outgoing: output_buffer;
}

let inStream  (c:ConnectionInfo) state =
    match state.app_incoming with
    | NoneIBuf(s) -> s
    | SomeIBuf(s,_,_) -> s

let outStream (c:ConnectionInfo) state =
    match state.app_outgoing with
    | NoneOBuf(s) -> s
    | SomeOBuf(s,_,_,_) -> s

let init ci =
  let ki_in = id ci.id_in in
  let ki_out = id ci.id_out in
  let in_s = DataStream.init ki_in in
  let out_s = DataStream.init ki_out in
    {app_outgoing = (NoneOBuf(out_s));
     app_incoming = (NoneIBuf(in_s))
    }

// Stores appdata in the output buffer, so that it will possibly sent on the network
let writeAppData (c:ConnectionInfo) (a:app_state) (r:range) (f:AppFragment.plain) (s':stream) =
    let s = outStream c a in
    {a with app_outgoing = SomeOBuf(s,r,f,s')}

let noneOutBuf ki s = NoneOBuf(s)
let some x = Some x
// When polled, gives Dispatch the next fragment to be delivered,
// and commits to it (adds it to the output stream)
let next_fragment (c:ConnectionInfo) (a:app_state) =
    let out = a.app_outgoing in
    match out with
    | NoneOBuf(_) -> None
    | SomeOBuf (s,r,f,s') ->
        let b' = noneOutBuf c.id_out s' in
        some (r,f,{a with app_outgoing = b'})

// Clear contents from the output buffer
let clearOutBuf (c:ConnectionInfo) (a:app_state) =
    let s = outStream c a in
    {a with app_outgoing = NoneOBuf(s)}

// Gets a fragment from Dispatch, adds it to the incoming buffer, but not yet to
// the stream of data delivered to the user
let recv_fragment (ci:ConnectionInfo)  (a:app_state)  (r:range) (f:AppFragment.fragment) =
    // pre: snd a.app_incoming = None
    match a.app_incoming with
    | NoneIBuf(s) ->
        {a with app_incoming = (SomeIBuf(s,r,f))}
    | SomeIBuf(_,_,_) -> unexpected "[recv_fragment] invoked with non-empty buffer"

// Returns the buffered data to the user, and stores them in the stream
let readAppData (c:ConnectionInfo) (a:app_state) =
    match a.app_incoming with
      | NoneIBuf(_) -> None,a
      | SomeIBuf(s,r,f) ->
          let (d,ns) = AppFragment.delta c.id_in s r f in
          let rd = (r,d) in
          Some(rd),{a with app_incoming = NoneIBuf(ns)}


let reset_outgoing (ci:ConnectionInfo) (a:app_state) (nci:ConnectionInfo) = 
  let ki = id nci.id_out in
  let out_s = DataStream.init ki in
    {a with 
       app_outgoing = NoneOBuf(out_s)
    }

let reset_incoming (ci:ConnectionInfo) (a:app_state) (nci:ConnectionInfo) = 
  let ki = id nci.id_in in
  let in_s = DataStream.init ki in
    {a with 
       app_incoming =  NoneIBuf(in_s)
    }
