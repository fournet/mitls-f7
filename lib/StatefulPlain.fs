module StatefulPlain
open Bytes
open TLSConstants
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

let statefulPlain (ki:epoch) (h:history) (ad:data) (r:range) (b:bytes) = {contents = Fragment.fragmentPlain ki r b}
let statefulRepr (ki:epoch) (h:history) (ad:data) (r:range) (f:statefulPlain) = Fragment.fragmentRepr ki r f.contents

let contents  (ki:epoch) (h:history) (ad:data) (rg:range) f = f.contents
let construct (ki:epoch) (h:history) (ad:data) (rg:range) c = {contents = c}

let makeAD ki ct =
    let si = epochSI(ki) in
    let pv = si.protocol_version in
    let bct  = ctBytes ct in
    let bver = versionBytes pv in
    if pv = SSL_3p0 
    then bct
    else bct @| bver

let TLSFragmentToFragment ki ct ss st rg f =
  let sb = TLSFragment.contents ki ct ss rg f in
  let ad = makeAD ki ct in
  construct ki st ad rg sb

let fragmentToTLSFragment ki ct ss st rg f =
  let ad = makeAD ki ct in
  let sb = contents ki st ad rg f in
  TLSFragment.construct ki ct ss rg sb
