module StatefulPlain
open Bytes
open Formats
open TLSInfo
open DataStream

type data = bytes

type prehistory =
  | Empty
  | ConsHistory of prehistory * data * range * Fragment.fragment
type history = (nat * prehistory)

type preds =
  | History of epoch * (nat * prehistory)

type prefragment = Fragment.fragment
type fragment = {contents: prefragment}

let consHistory (ki:epoch) h d r f = ConsHistory(h,d,r,f)

let emptyHistory (ki:epoch) = (0,Empty)
let addToHistory (ki:epoch) sh d r x = 
  let (seqn,h) = sh in
  let f = x.contents in
  let s' = seqn+1 in
  let nh = consHistory ki h d r f in
  let res = (s',nh) in
    Pi.assume(History(ki,res));
    res

let makeAD (ki:epoch) ((seqn,h):history) ad =
  let bn = bytes_of_seq seqn in
  bn @| ad

let fragment (ki:epoch) (h:history) (ad:data) (r:range) (b:bytes) = {contents = Fragment.fragmentPlain ki r b}
let repr (ki:epoch) (h:history) (ad:data) (r:range) (f:fragment) = Fragment.fragmentRepr ki r f.contents

let contents  (ki:epoch) (h:history) (ad:data) (rg:range) f = f.contents
let construct (ki:epoch) (h:history) (ad:data) (rg:range) c = {contents = c}

let FragmentToAEADPlain ki h ad r f =
  let ad' = makeAD ki h ad in
  let fr = f.contents in
  AEADPlain.construct ki r ad' fr

let AEADPlainToFragment ki h ad r p =
  let ad' = makeAD ki h ad in
  let f = AEADPlain.contents ki r ad' p in
  {contents = f}


