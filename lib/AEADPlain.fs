module AEADPlain
open Error
open Bytes
open TLSInfo
open DataStream
open StatefulPlain

type data = bytes
type plain = sbytes

let plain (ki:KeyInfo) (rg:range) (ad:data) b = DataStream.plain ki rg b

let repr  (ki:KeyInfo) (rg:range) (ad:data) p = DataStream.repr ki rg p

let fragmentToPlain (ki:KeyInfo) (h:history) (ad:data) (rg:range) (f:fragment) :plain= f

let plainToFragment (ki:KeyInfo) (h:history) (ad:data) (rg:range) (p:plain) = p