module LHAEPlain
open Bytes
open Error
open TLSError
open TLSConstants
open TLSInfo
open Range

type adata = bytes

let makeAD (e:epoch) ((seqn,h):StatefulPlain.history) ad =
  let bn = bytes_of_seq seqn in
  bn @| ad

// We statically know that ad is big enough
let parseAD (e:epoch) ad = 
  let (snb,ad) = Bytes.split ad 8 in
    ad

type fragment = {contents:StatefulPlain.fragment}
type plain = fragment

(*
let widenRange (e:epoch) (d:adata) (rg:range) (p:plain) (rg':range) = p 
*)

let plain (e:epoch) (ad:adata) (rg:range) b =
    let ad = parseAD e ad in
    let h = StatefulPlain.emptyHistory e in
    {contents = StatefulPlain.plain e h ad rg b}

let reprFragment (e:epoch) (ad:adata) (rg:range) p =
    let ad = parseAD e ad in
    StatefulPlain.reprFragment e ad rg p.contents

let repr e ad rg p = reprFragment e ad rg p

let StatefulPlainToLHAEPlain (e:epoch) (h:StatefulPlain.history) 
    (ad:StatefulPlain.adata) (ad':adata) (r:range) f = {contents = f}
let LHAEPlainToStatefulPlain (e:epoch) (h:StatefulPlain.history) 
    (ad:StatefulPlain.adata) (ad':adata) (r:range) f = f.contents

#if ideal
let widen e ad r f =
    let ad' = parseAD e ad in
    let f' = StatefulPlain.widen e ad' r f.contents in
    {contents = f'}
#endif
