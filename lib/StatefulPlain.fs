module StatefulPlain
open Error
open Bytes
open TLSInfo
open TLSKey
open DataStream
open Formats

type data = bytes
type prestate = {
  key: AEADKey;
  iv: ENCKey.iv3;
  seqn: int;
  history: (data * range * TLSFragment.fragment) list;
}
type state = prestate
type writer = state
type reader = state
type fragment = {f:TLSFragment.fragment}

let initState (ki:KeyInfo) k i = {key = k; iv = i; seqn = 0; history = []}
let getKey (ki:KeyInfo) s = s.key
let getIV (ki:KeyInfo) s = s.iv
let sequenceNo (ki:KeyInfo) s = s.seqn
let updateIV (ki:KeyInfo) s i = {s with iv = i}
let addFragment (ki:KeyInfo) s d r f = {s with history = (d,r,f.f) :: s.history}

let parseAD ad = 
  let bs,ad' = Bytes.split ad 8 in
  let n = seq_of_bytes bs in 
    (n,ad')

let makeAD n ad =
  let bn = bytes_of_seq n in
    bn @| ad



let fragment (ki:KeyInfo) (fs:state) (ad:bytes) (r:range) (b:bytes) = 
  let (seq,ad') = parseAD ad in
  let ct = TLSFragment.parseAD ki.sinfo.protocol_version ad' in
    {f = TLSFragment.TLSFragment ki r 0 ct b}

let repr (ki:KeyInfo) (fs:state) (ad:bytes) (r:range) (b:fragment) = 
  let (seq,ad') = parseAD ad in
  let ct = TLSFragment.parseAD ki.sinfo.protocol_version ad' in
    TLSFragment.TLSFragmentRepr ki r 0 ct b.f

let TLSFragmentToFragment (ki:KeyInfo) (r:range) (seq:int) (ct:ContentType) (f:TLSFragment.fragment) = {f = f}

let fragmentToTLSFragment (ki:KeyInfo) (fs:state) (ad:bytes) (r:range) (f:fragment) = f.f

let emptyState (ki:KeyInfo) : state = failwith "emptyState should never be used"
