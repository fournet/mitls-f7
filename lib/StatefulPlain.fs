module StatefulPlain
open TLSInfo
open DataStream

type fragmentSequence = (bytes * TLSFragment.fragment) list
type fragment = TLSFragment.fragment

let sequenceLength (ki:KeyInfo) (f:fragmentSequence) = List.length f

let addFragment (ki:KeyInfo) (fs:fragmentSequence) (ad:bytes) (r:range) (f:fragment) = fs @ [(ad,f)]


let TLSFragmentToFragment (k:KeyInfo) (r:range) (n:int) (f:TLSFragment.fragment) = f
let FragmentToTLSFragment (k:KeyInfo) (r:range) (n:int) (f:fragment) = f
  
let fragment (ki:KeyInfo) (fs:fragmentSequence) (ad:bytes) (r:range) (b:bytes) = 
  TLSFragment.TLSFragment ki r 0
