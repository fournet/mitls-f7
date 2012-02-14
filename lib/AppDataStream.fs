module AppDataStream

open Error
open Bytes
open TLSInfo
open DataStream

type preds = 
    AppDataFragmentSequence of KeyInfo * int * bytes
  | AppDataFragment of KeyInfo * int * int * bytes
  | NonAppDataSequenceNo of KeyInfo * int
  | AppDataSequenceNo of KeyInfo * int
  | ValidAppDataStream of KeyInfo * bytes

type buffer = {
  seqn: int;
  history: stream;
  full: stream;
  data: (range * delta) option;
}

type input_buffer = buffer
type output_buffer = buffer

type app_state = {
  app_incoming: input_buffer;
  app_outgoing: output_buffer;
}

let init ci =
  let in_s = DataStream.init ci.id_in in
  let out_s = DataStream.init ci.id_out in
    {app_outgoing = 
        {seqn = 0;
         history = out_s;
         full = out_s;
         data = None};
     app_incoming = 
        {seqn = 0;
         history = in_s;
         full = in_s;
         data = None};
    }

let is_incoming_empty (ci:ConnectionInfo) app_state = 
  app_state.app_incoming.data = None

let is_outgoing_empty (ci:ConnectionInfo)  app_state = 
  app_state.app_outgoing.data = None
    
type fragment = delta

let repr (ki:KeyInfo) (r:DataStream.range) (seqn:int) (d:fragment) = 
  let s = DataStream.init ki in
  deltaRepr ki s r d

let fragment (ki:KeyInfo)  (r:DataStream.range) (seqn:int) (b:bytes) = 
  let s = DataStream.init ki in
  delta ki s r b

let writeAppData (c:ConnectionInfo)  (a:app_state) (r:range) (d:delta) =
  let f = a.app_outgoing.full in
  let h = a.app_outgoing.history in
  let b = a.app_outgoing.data in
  let nf = append c.id_out f r d in
  let ndata = 
    match b with  
        None -> Some(r,d) 
      | Some (rr,dd) -> Some (rangeSum rr r, 
                              join c.id_out h rr d r d) in
  {a with app_outgoing = {a.app_outgoing with full = nf; data = ndata}}

let readAppData (c:ConnectionInfo)  (a:app_state) = 
  let h = a.app_incoming.history in
  let b = a.app_incoming.data in
    match b with
        None -> None,{a with app_incoming = {a.app_incoming with data = None}}
      | Some(r,d) -> 
          let nh = DataStream.append c.id_in h r d in
          Some(r,d),{a with app_incoming = {a.app_incoming with history = nh;data = None}}

let readAppDataFragment (c:ConnectionInfo)  (a:app_state) =
  let h = a.app_outgoing.history in
    Pi.assume(AppDataSequenceNo(c.id_out,a.app_outgoing.seqn));
    match a.app_outgoing.data with
        None -> None
      | Some (r,d) -> 
          let r1 = (0,1) in
          let r2 = r in
          let (d1,d2) = DataStream.split c.id_out h r1 r2 d in
          let stream = DataStream.append c.id_out h r1 d1 in
            Some(r1,d1,{a with app_incoming = {a.app_incoming with history = stream; data = Some(r2,d2)}})

let readNonAppDataFragment (c:ConnectionInfo) (a:app_state) = 
  let nout_seqn = a.app_outgoing.seqn + 1 in
    Pi.assume(NonAppDataSequenceNo(c.id_out,a.app_outgoing.seqn));
    {a with app_outgoing = {a.app_outgoing with seqn = nout_seqn}}

let writeNonAppDataFragment (c:ConnectionInfo)  (a:app_state) = 
  let seqn = a.app_incoming.seqn in
  let nseqn = seqn + 1 in
    Pi.assume(NonAppDataSequenceNo(c.id_in,seqn));
    {a with app_incoming = {a.app_incoming with seqn = nseqn}}
    
let writeAppDataFragment (ci:ConnectionInfo)  (a:app_state)  (r:range) (d:fragment) =
  let seqn = a.app_incoming.seqn in
  Pi.assume(AppDataSequenceNo(ci.id_in,seqn));
  let nseqn = seqn + 1 in
  let f = a.app_incoming.full in
  let h = a.app_incoming.history in
  let nf = append ci.id_in f r d in
  match a.app_incoming.data with
      None -> 
        {a with app_incoming = {a.app_incoming with data = Some(r,d); full = nf}}
    | Some(rr,dd) ->
        let nd = join ci.id_in h rr dd r d in
        let nr = rangeSum rr r in
        {a with app_incoming = {a.app_incoming with data = Some(nr,nd); full = nf}}

let reIndex (oldC:ConnectionInfo)  (newC:ConnectionInfo) (a:app_state) = a

let reset_outgoing (ci:ConnectionInfo) (a:app_state) = 
  let out_s = DataStream.init ci.id_out in
    {a with 
       app_outgoing = 
        {seqn = 0;
         history = out_s;
         full = out_s;
         data = None};
    }

let reset_incoming (ci:ConnectionInfo) (a:app_state) = 
  let in_s = DataStream.init ci.id_in in
    {a with 
       app_incoming = 
        {seqn = 0;
         history = in_s;
         full = in_s;
         data = None};
    }
