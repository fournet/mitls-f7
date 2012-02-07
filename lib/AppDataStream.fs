module AppDataStream

open Error
open Bytes
open TLSInfo
open FragCommon


type lengths = int list (* a list of desired ciphertext lengths *)
type preAppDataStream = {
  history: bytes;
  lengths_history: lengths;
  data: bytes;
  lengths: lengths; 
}
type AppDataStream = preAppDataStream

type preds = 
    AppDataFragmentSequence of KeyInfo * int * bytes
  | AppDataFragment of KeyInfo * int * int * bytes
  | NonAppDataSequenceNo of KeyInfo * int
  | AppDataSequenceNo of KeyInfo * int
  | ValidAppDataStream of KeyInfo * bytes

let emptyAppDataStream (si:KeyInfo) = 
  {
    history = [| |];
    lengths_history = [];
    data = [| |];
    lengths = [];
  }

let isEmptyAppDataStream (si:KeyInfo) (ls:lengths) 
    (ads:AppDataStream) = equalBytes ads.data [||]

let writeAppDataStreamBytes (si:KeyInfo) (ls:lengths) 
    (ads:AppDataStream) (data:bytes) (lens:lengths) = 
  let ndata = ads.data @| data in
  let nlengths = ads.lengths @ lens in
  let nls = ls @ lens in
  (nls,{ads with data = ndata; lengths = nlengths})

let readAppDataStreamBytes (si:KeyInfo) (ls:lengths) (ads:AppDataStream) = 
  let nhistory = ads.history @| ads.data in
  let nlengths_history = ads.lengths_history @ ads.lengths in
  (ads.data,
   {history = nhistory; 
    lengths_history = nlengths_history;
    data = [| |];
    lengths = []})

type output_buffer = int * lengths * AppDataStream
type input_buffer = int * lengths * AppDataStream

type app_state = {
  app_incoming: input_buffer;
  app_outgoing: output_buffer;
}

let init ci =
  let in_ads = emptyAppDataStream ci.id_in in
  let out_ads = emptyAppDataStream ci.id_out in
    {app_outgoing = (0,[],out_ads);
     app_incoming = (0,[],in_ads);
    }

let is_incoming_empty (ci:ConnectionInfo) app_state = 
  let (seqn,ls,ads) = app_state.app_incoming in
    isEmptyAppDataStream ci.id_in ls ads

let is_outgoing_empty (ci:ConnectionInfo)  app_state = 
  let (seqn,ls,ads) = app_state.app_outgoing in
    isEmptyAppDataStream ci.id_out ls ads
    

type fragment = {b:bytes}

let repr (ki:KeyInfo) (i:int) (seqn:int) f = f.b
let fragment (ki:KeyInfo) (i:int) (seqn:int) b = {b=b}

let mkFragment (ki:KeyInfo) (tlen:int) (seqn:int) f = 
  Pi.assume(AppDataFragment(ki,tlen,seqn,f));
  {b = f}

let writeAppDataBytes (c:ConnectionInfo)  (a:app_state) (b:bytes) (lens:lengths) = 
  let (seqn,ls,ads) = a.app_outgoing in
  let ki = c.id_out in 
  let stream = ads.history @| ads.data @| b in
  Pi.assume(ValidAppDataStream(ki,stream));
    let (nls,nads) = writeAppDataStreamBytes ki ls ads b lens in
    {a with app_outgoing = (seqn,nls,nads);}

let readAppDataBytes (c:ConnectionInfo)  (a:app_state) = 
  let (seqn,ls,ads) = a.app_incoming in
  let ki = c.id_in in
  let (b,nads) = readAppDataStreamBytes ki ls ads in
    (b,{a with app_incoming = (seqn,ls,nads)})

(* The idea is: Given the cipertext target length, we get a *smaller* plaintext fragment
   (so that MAC and padding can be added back).
   In practice: since estimateLengths acts deterministically on the appdata length, we do the same here, and
   we rely on the fact that the implementation here is the same in estimateLenghts, so that our fragment size is
   always aligned with the estimated ones.
   TODO: we should also perform compression *now*. After we extract the next fragment from appdata, we compress it
   and only after we return it. The target length will be compatible with the compressed length, because the
   estimateLengths function takes compression into account. *)

let readAppDataFragment (c:ConnectionInfo)  (a:app_state) =
  let (out_seqn,out_ls,out_ads) = a.app_outgoing in
  let nout_seqn = out_seqn + 1 in
  match out_ads.lengths with 
    | thisLen::remLens ->
    Pi.assume(AppDataSequenceNo(c.id_out,out_seqn));
    let (thisData,remData) = getFragment c.id_out.sinfo thisLen out_ads.data in
        let f = mkFragment c.id_out thisLen out_seqn thisData in
    let nout_ads = 
       {history = out_ads.history @| thisData;
        lengths_history = out_ads.lengths_history @ [thisLen];
        data = remData;
        lengths = remLens;} in
    Some (thisLen,f, {a with app_outgoing = (nout_seqn,out_ls,nout_ads)})
    | [] -> None


let readNonAppDataFragment (c:ConnectionInfo) (a:app_state) = 
  let (out_seqn,out_ls,out_ads) = a.app_outgoing in
  let nout_seqn = out_seqn + 1 in
    Pi.assume(NonAppDataSequenceNo(c.id_out,out_seqn));
    {a with app_outgoing = (nout_seqn,out_ls,out_ads)}


let writeNonAppDataFragment (c:ConnectionInfo)  (a:app_state) = 
  let (seqn,ls,ads) = a.app_incoming in
  let nseqn = seqn + 1 in
    Pi.assume(NonAppDataSequenceNo(c.id_in,seqn));
    {a with app_incoming = (nseqn,ls,ads)}

    


let writeAppDataFragment (c:ConnectionInfo)  (a:app_state)  (tlen:int) (f:fragment) =
  let (seqn,ls,ads) = a.app_incoming in
  Pi.assume(AppDataSequenceNo(c.id_in,seqn));
  let nseqn = seqn + 1 in
  let fb = f.b in
  let ndata = ads.data @| fb in
  let nlens = ads.lengths @ [tlen] in
  let nls = ls @ [tlen] in
  let nads = {ads with data = ndata;
                       lengths = nlens;} in
  {a with app_incoming = (nseqn,nls,nads)}

let reIndex (oldC:ConnectionInfo)  (newC:ConnectionInfo) (a:app_state) = a


let reset_incoming (newC:ConnectionInfo) (a:app_state) = 
  let (seqn,ls,b) = a.app_incoming in
    {a with 
       app_incoming = (0,ls,b);
    }

let reset_outgoing (newC:ConnectionInfo) (a:app_state) = 
  let (seqn,ls,b) = a.app_outgoing in
    {a with 
       app_outgoing = (0,ls,b);
    }
