module AEADPlain
open Error
open Bytes
open TLSInfo
open DataStream
open StatefulPlain

type data = bytes
type plain = {p : bytes}

let plain (ki:KeyInfo) (rg:range) (ad:data) b = {p=b}

let repr  (ki:KeyInfo) (rg:range) (ad:data) p = p.p

let fragmentToPlain (ki:KeyInfo) (h:TLSFragment.history) (ad:data) (rg:range) (f:fragment) =
    {p = StatefulPlain.repr ki h ad rg f}

let plainToFragment (ki:KeyInfo) (h:TLSFragment.history) (ad:data) (rg:range) (p:plain) =
    StatefulPlain.fragment ki h ad rg p.p