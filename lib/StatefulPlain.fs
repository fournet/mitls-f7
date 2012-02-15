module StatefulPlain
open Error
open Bytes
open TLSInfo
open DataStream
open Formats

type addData = bytes
type fragmentSequence = (bytes * TLSFragment.fragment) list
type fragment = TLSFragment.fragment
type state = {
  history: fragmentSequence
}

let emptyState (ki:KeyInfo) : state = {history = []}
let stateLength (ki:KeyInfo) (f:state) = List.length (f.history)
let addFragment (ki:KeyInfo) (fs:state) (ad:bytes) (r:range) (f:fragment) = 
  {history = fs.history @ [(ad,f)]}



let parseAD ad = 
  let bs,ad' = Bytes.split ad 8 in
  let n = seq_of_bytes bs in 
    (n,ad')

let makeAD n ad =
  let bn = bytes_of_seq n in
    bn @| ad


let TLSFragmentToFragment (ki:KeyInfo) (r:range) (seq:int) (ct:ContentType) (f:TLSFragment.fragment) = f

let fragmentToTLSFragment (ki:KeyInfo) (fs:state) (ad:bytes) (r:range) (f:fragment) = f

let fragment (ki:KeyInfo) (fs:state) (ad:bytes) (r:range) (b:bytes) = 
  let (seq,ad') = parseAD ad in
  let ct = TLSFragment.parseAD ki.sinfo.protocol_version ad' in
    TLSFragment.TLSFragment ki r 0 ct b

let repr (ki:KeyInfo) (fs:state) (ad:bytes) (r:range) (b:fragment) = 
  let (seq,ad') = parseAD ad in
  let ct = TLSFragment.parseAD ki.sinfo.protocol_version ad' in
    TLSFragment.TLSFragmentRepr ki r 0 ct b
