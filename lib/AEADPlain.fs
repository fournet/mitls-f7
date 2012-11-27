module AEADPlain
open Bytes
open TLSConstants
open TLSInfo

type data = bytes

let makeAD (ki:epoch) ((seqn,h):StatefulPlain.history) ad =
  let bn = bytes_of_seq seqn in
  bn @| ad

let parseAD (e:epoch) ad =
    if length ad > 8 then
        let (sn,ad) = Bytes.split ad 8 in
        ad
    else
        Error.unexpectedError "[parseAD] should never fail parsing"

type AEADPlain = {contents:StatefulPlain.statefulPlain}

let AEADPlain (ki:epoch) (rg:range) (ad:data) b =
    let ad = parseAD ki ad in
    let h = StatefulPlain.emptyHistory ki in
    {contents = StatefulPlain.statefulPlain ki h ad rg b}

let AEADRepr  (ki:epoch) (rg:range) (ad:data) p =
    let ad = parseAD ki ad in
    let h = StatefulPlain.emptyHistory ki in
    StatefulPlain.statefulRepr ki h ad rg p.contents

let contents  (ki:epoch) (rg:range) (ad:data) p = p.contents
let construct (ki:epoch) (rg:range) (ad:data) b = {contents = b}

let StatefulToAEADPlain ki h ad r f =
  let ad' = makeAD ki h ad in
  construct ki r ad' f

let AEADPlainToStateful ki h ad r p =
  let ad' = makeAD ki h ad in
  contents ki r ad' p