module AEADPlain
open Bytes
open TLSConstants
open TLSInfo

type adata = bytes

let makeAD (e:epoch) ((seqn,h):StatefulPlain.history) ad =
  let bn = bytes_of_seq seqn in
  bn @| ad

let parseAD (e:epoch) ad =
    let lad = length ad in
    if lad > 8 then
        let (sn,ad) = Bytes.split ad 8 in
        ad
    else
        Error.unexpectedError "[parseAD] should never fail parsing"

type fragment = {contents:StatefulPlain.fragment}
type plain = fragment

let plain (e:epoch) (ad:adata) (rg:range) b =
    let ad = parseAD e ad in
    let h = StatefulPlain.emptyHistory e in
    {contents = StatefulPlain.plain e h ad rg b}

let reprFragment (e:epoch) (ad:adata) (rg:range) p =
    let ad = parseAD e ad in
    StatefulPlain.reprFragment e ad rg p.contents

let repr e ad rg p = reprFragment e ad rg p

//let contents  (e:epoch) (rg:range) (ad:data) p = p.contents
//let construct (e:epoch) (rg:range) (ad:data) b = {contents = b}

let StatefulPlainToAEADPlain (e:epoch) (h:StatefulPlain.history) (ad:adata) (r:range) f = {contents = f}
  //let ad' = makeAD e h ad in
  //construct e r ad' f

let AEADPlainToStatefulPlain (e:epoch) (h:StatefulPlain.history) (ad:adata) (r:range) f = f.contents
  //let ad' = makeAD e h ad in
  //contents e r ad' p