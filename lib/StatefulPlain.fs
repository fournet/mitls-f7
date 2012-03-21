module StatefulPlain
open Error
open Bytes
open TLSInfo
open DataStream
open Formats

type data = bytes

type fragment = {f:bytes}

let parseAD ad = 
  let bs,ad' = Bytes.split ad 8 in
  let n = seq_of_bytes bs in 
    (n,ad')

let makeAD n ad =
  let bn = bytes_of_seq n in
    bn @| ad

let fragment (ki:KeyInfo) (h:TLSFragment.history) (ad:bytes) (r:range) (b:bytes) = {f=b}

let repr (ki:KeyInfo) (h:TLSFragment.history) (ad:bytes) (r:range) (f:fragment) = f.f

let TLSFragmentToFragment (ki:KeyInfo) (ct:ContentType) (h:TLSFragment.history) (rg:DataStream.range) (f:TLSFragment.fragment) =
    {f = TLSFragment.TLSFragmentRepr ki ct h rg f}
let fragmentToTLSFragment (ki:KeyInfo) (ct:ContentType) (h:TLSFragment.history) (rg:range) (f:fragment) =
    TLSFragment.TLSFragment ki ct h rg f.f

let addFragment (ki:KeyInfo) h d r f =
 // FIXME: This function looks like an hack that breaks abstraction.
 // It should only be present in TLSFragment, not in StatefulPlain
 let ct = TLSFragment.parseAD ki.sinfo.protocol_version d in
 let fr = fragmentToTLSFragment ki ct h r f in
 TLSFragment.addFragment ki ct h r fr
