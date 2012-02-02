#light "off"
module AppDataStream

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

type lengthPreds =
   CompatibleLengths of SessionInfo * int * lengths

let rec estimateLengths sinfo len =
  let ls = 
    if len > fragmentLength then 
        cipherLength sinfo fragmentLength :: 
        estimateLengths sinfo (len - fragmentLength)  
    else 
        [cipherLength sinfo len] in
  Pi.assume (CompatibleLengths(sinfo,len,ls));
  ls

let emptyAppDataStream (si:SessionInfo) = 
  {
    history = [| |];
    lengths_history = [];
    data = [| |];
    lengths = [];
  }

let isEmptyAppDataStream (si:SessionInfo) (i:int) (ls:lengths) 
    (ads:AppDataStream) = equalBytes ads.data [||]

let writeAppDataBytes (si:SessionInfo) (seqn:int) (ls:lengths) 
    (ads:AppDataStream) (data:bytes) (lens:lengths) = 
  let ndata = ads.data @| data in
  let nlengths = ads.lengths @ lens in
  let nls = ls @ lens in
  (nls,{ads with data = ndata; lengths = nlengths})

let readAppDataBytes (si:SessionInfo) (seqn:int) (ls:lengths) (ads:AppDataStream) = 
  let nhistory = ads.history @| ads.data in
  let nlengths_history = ads.lengths_history @ ads.lengths in
  (ads.data,
   {history = nhistory; 
    lengths_history = nlengths_history;
    data = [| |];
    lengths = []})

type fragment = {b:bytes}
let repr (ki:KeyInfo) (i:int) (seqn:int) f = f.b
let fragment (ki:KeyInfo) (i:int) (seqn:int) b = {b=b}


let writeAppDataFragment (ki:KeyInfo) (seqn:int) (ls:lengths) 
    (ads:AppDataStream) (nseqn:int) (tlen:int) (f:fragment) =
  let ndata = ads.data @| f.b in
  let nlens = ads.lengths @ [tlen] in
  let nls = ls @ [tlen] in
    nls,{ads with
	   data = ndata;
	   lengths = nlens;
	}

(* The idea is: Given the cipertext target length, we get a *smaller* plaintext fragment
   (so that MAC and padding can be added back).
   In practice: since estimateLengths acts deterministically on the appdata length, we do the same here, and
   we rely on the fact that the implementation here is the same in estimateLenghts, so that our fragment size is
   always aligned with the estimated ones.
   TODO: we should also perform compression *now*. After we extract the next fragment from appdata, we compress it
   and only after we return it. The target length will be compatible with the compressed length, because the
   estimateLengths function takes compression into account. *)

let readAppDataFragment (ki:KeyInfo) (seqn:int) (ls:lengths) (ads:AppDataStream) 
    (nseqn:int) = 
  match ads.lengths with 
    | thisLen::remLens ->
	let dlen = Bytes.length(ads.data) in
        (* Same implementation as estimateLengths, but one fragment at a time *)
        if dlen > fragmentLength then
            (* get one full fragment of appdata *)
            (* TODO: apply compression on thisData *)
            let (thisData,remData) = split ads.data fragmentLength in
	      (thisLen,{b = thisData},
	       {history = ads.history @| thisData;
		lengths_history = ads.lengths_history @ [thisLen];
		data = remData;
		lengths = remLens;})
        else
	      (thisLen,{b = ads.data},
	       {history = ads.history @| ads.data;
		lengths_history = ads.lengths_history @ [thisLen];
		data = [| |];
		lengths = remLens;}) // KB:there should be no remaining lengths?
    | [] -> (0,{b = [||]},ads)


let reIndex (oldSI:SessionInfo) (newSI:SessionInfo) (seqn:int) (ls:lengths) 
    (ads:AppDataStream) = ads
