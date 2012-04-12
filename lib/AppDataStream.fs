module AppDataStream

open Error
open Bytes
open TLSInfo
open DataStream

type buffer = {
  stream:stream;
  data: stream * (range * delta) option;
}

type input_buffer = buffer
type output_buffer = buffer

type app_state = {
  app_incoming: input_buffer;
  app_outgoing: output_buffer;
}

let inStream  (c:ConnectionInfo) state = state.app_incoming.stream
let outStream (c:ConnectionInfo) state = state.app_outgoing.stream

let init ci =
  let in_s = DataStream.init ci.id_in in
  let out_s = DataStream.init ci.id_out in
    {app_outgoing = 
        {stream = out_s;
         data = (out_s,None)};
     app_incoming = 
        {stream = in_s;
         data = (in_s,None)};
    }

let is_incoming_empty (ci:ConnectionInfo) app_state = 
  snd app_state.app_incoming.data = None

let is_outgoing_empty (ci:ConnectionInfo)  app_state = 
  snd app_state.app_outgoing.data = None

let repr (ki:KeyInfo) (s:stream) (r:DataStream.range) (d:delta) = 
  //let s = DataStream.init ki in // AP: why?
  deltaRepr ki s r d

let fragment (ki:KeyInfo) (s:stream)  (r:DataStream.range) (b:bytes) = 
  //let s = DataStream.init ki in // AP: why?
  delta ki s r b

let writeAppData (c:ConnectionInfo)  (a:app_state) (r:range) (d:delta) =
  let f = a.app_outgoing.stream in
  let b = a.app_outgoing.data in
  let nf = append c.id_out f r d in
  let ndata = 
    match b with  
        h,None -> h,Some(r,d) 
      | h,Some (rr,dd) -> h,Some (rangeSum rr r, 
                              join c.id_out h rr dd r d) in
  {a with app_outgoing = {a.app_outgoing with stream = nf; data = ndata}}

let readAppData (c:ConnectionInfo)  (a:app_state) = 
  let b = a.app_incoming.data in
    match b with
        h,None -> None,{a with app_incoming = {a.app_incoming with data = h,None}}
      | h,Some(r,d) -> 
          let nh = DataStream.append c.id_in h r d in
          Some(r,d),{a with app_incoming = {a.app_incoming with data = nh,None}}

(* Breaks invariants, but we shouldn't be relying on histories over here anymore *)
let emptyOutgoingAppData (c:ConnectionInfo)  (a:app_state) = 
  let b = a.app_outgoing.data in
    match b with
      | h,None -> None,a
      | h,Some(r,d) -> 
          Some(r,d),{a with app_outgoing = {a.app_outgoing with data = h,None}}
    
let readAppDataFragment (c:ConnectionInfo)  (a:app_state) =
    // Pi.assume(AppDataSequenceNo(c.id_out,a.app_outgoing.seqn));
    match a.app_outgoing.data with
        hs,None -> None
      | hs,Some (r,d) ->
          let (r0,r1) = splitRange c.id_out r in
          if r = r0 then
            let stream = DataStream.append c.id_out hs r d in
            Some(r,d,{a with app_outgoing = {a.app_outgoing with data = stream,None}})
          else 
            let (d0,d1) = DataStream.split c.id_out hs r0 r1 d in
            let stream = DataStream.append c.id_out hs r0 d0 in
            Some(r0,d0,{a with app_outgoing = {a.app_outgoing with data = stream,Some(r1,d1)}})

// let readNonAppDataFragment (c:ConnectionInfo) (a:app_state) = 
//   let nout_seqn = a.app_outgoing.seqn + 1 in
//     Pi.assume(NonAppDataSequenceNo(c.id_out,a.app_outgoing.seqn));
//     {a with app_outgoing = {a.app_outgoing with seqn = nout_seqn}}

// let writeNonAppDataFragment (c:ConnectionInfo)  (a:app_state) = 
//   let seqn = a.app_incoming.seqn in
//   let nseqn = seqn + 1 in
//     Pi.assume(NonAppDataSequenceNo(c.id_in,seqn));
//     {a with app_incoming = {a.app_incoming with seqn = nseqn}}
    
let writeAppDataFragment (ci:ConnectionInfo)  (a:app_state)  (r:range) (d:delta) =
  // let seqn = a.app_incoming.seqn in
  // Pi.assume(AppDataSequenceNo(ci.id_in,seqn));
  // let nseqn = seqn + 1 in
  let f = a.app_incoming.stream in
  let nf = append ci.id_in f r d in
  match a.app_incoming.data with
      h,None -> 
        {a with app_incoming = {a.app_incoming with data = h,Some(r,d); stream = nf}}
    | h,Some(rr,dd) ->
        let nd = join ci.id_in h rr dd r d in
        let nr = rangeSum rr r in
        {a with app_incoming = {a.app_incoming with data = h,Some(nr,nd); stream = nf}}

let reset_outgoing (ci:ConnectionInfo) (a:app_state) = 
  let out_s = DataStream.init ci.id_out in
    {a with 
       app_outgoing = 
        {stream = out_s;
         data = out_s,None};
    }

let reset_incoming (ci:ConnectionInfo) (a:app_state) = 
  let in_s = DataStream.init ci.id_in in
    {a with 
       app_incoming = 
        {stream = in_s;
         data = in_s,None};
    }
