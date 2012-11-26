module AEADPlain
open Bytes
open TLSConstants
open TLSInfo
open DataStream
open Fragment
open StatefulPlain

type data = bytes
type preAEADPlain = fragment
type AEADPlain = {contents:preAEADPlain}

let AEADPlain (ki:epoch) (rg:range) (ad:data) b = {contents = fragmentPlain ki rg b}
let AEADRepr  (ki:epoch) (rg:range) (ad:data) p = fragmentRepr ki rg p.contents

let contents  (ki:epoch) (rg:range) (ad:data) p = p.contents
let construct (ki:epoch) (rg:range) (ad:data) b = {contents = b}

let makeAD (ki:epoch) ((seqn,h):history) ad =
  let bn = bytes_of_seq seqn in
  bn @| ad

let StatefulToAEADPlain ki h ad r f =
  let ad' = makeAD ki h ad in
  let fr = StatefulPlain.contents ki h ad r f in
  construct ki r ad' fr

let AEADPlainToStateful ki h ad r p =
  let ad' = makeAD ki h ad in
  let f = contents ki r ad' p in
  StatefulPlain.construct ki h ad r f