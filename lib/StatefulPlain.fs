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

type prefragment = Fragment.fragment
type fragment = {contents: prefragment}

let emptyHistory (ki:KeyInfo) = (0,Empty)
let addToHistory (ki:KeyInfo) sh d r x = 
  let (seqn,h) = sh in
  let f = x.contents in
  let s' = seqn+1 in 
    (s',ConsHistory(h,d,r,f))

let makeAD (ki:KeyInfo) ((seqn,h):history) ad =
  let bn = bytes_of_seq seqn in
    bn @| ad

let fragment (ki:KeyInfo) (h:history) (ad:data) (r:range) (b:bytes) = {contents = Fragment.fragmentPlain ki r b}
let repr (ki:KeyInfo) (h:history) (ad:data) (r:range) (f:fragment) = Fragment.fragmentRepr ki r f.contents

let contents  (ki:KeyInfo) (h:history) (ad:data) (rg:range) f = f.contents
let construct (ki:KeyInfo) (h:history) (ad:data) (rg:range) c = {contents = c}

let FragmentToAEADPlain ki h ad r f =
    let ad' = makeAD ki h ad in
    AEADPlain.construct ki r ad' f.contents

let AEADPlainToFragment ki h ad r p =
    let ad' = makeAD ki h ad in
    let f = AEADPlain.contents ki r ad' p in
    {contents = f}


