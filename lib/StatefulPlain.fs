module StatefulPlain
open Bytes
open Formats
open TLSInfo
open DataStream

type data = bytes

type prehistory = (data * range * Fragment.fragment) list
type history = (nat * prehistory)


type statefulPlain = {contents: Fragment.fragment}

let consHistory (ki:epoch) h d r f = (d,r,f)::h

let emptyHistory (ki:epoch): history = (0,[])
let addToHistory (ki:epoch) (sh:history) d r x = 
  let (seqn,h) = sh in
  let f = x.contents in
  let s' = seqn+1 in
  let nh = consHistory ki h d r f in
  let res = (s',nh) in
    res

let makeAD (ki:epoch) ((seqn,h):history) ad =
  let bn = bytes_of_seq seqn in
  bn @| ad

let statefulPlain (ki:epoch) (h:history) (ad:data) (r:range) (b:bytes) = {contents = Fragment.fragmentPlain ki r b}
let statefulRepr (ki:epoch) (h:history) (ad:data) (r:range) (f:statefulPlain) = Fragment.fragmentRepr ki r f.contents

let contents  (ki:epoch) (h:history) (ad:data) (rg:range) f = f.contents
let construct (ki:epoch) (h:history) (ad:data) (rg:range) c = {contents = c}

let StatefulToAEADPlain ki h ad r f =
  let ad' = makeAD ki h ad in
  let fr = f.contents in
  AEADPlain.construct ki r ad' fr

let AEADPlainToStateful ki h ad r p =
  let ad' = makeAD ki h ad in
  let f = AEADPlain.contents ki r ad' p in
  {contents = f}


