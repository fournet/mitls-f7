module AEADPlain
open Bytes
open TLSInfo
open DataStream
open AEPlain

type data = bytes
type AEADPlain = {contents: sbytes}

let AEADPlain (ki:KeyInfo) (rg:range) (ad:data) b = {contents = DataStream.plain ki rg b}
let AEADRepr  (ki:KeyInfo) (rg:range) (ad:data) p = DataStream.repr ki rg p.contents

let contents  (ki:KeyInfo) (rg:range) (ad:data) p = p.contents
let construct (ki:KeyInfo) (rg:range) (ad:data) b = {contents = b}

let AEADPlainToAEPlain (ki:KeyInfo) (rg:range) (ad:data) p =
    AEConstruct ki rg ad p.contents
let AEPlainToAEADPlain (ki:KeyInfo) (rg:range) (ad:data) p =
    {contents = AEContents ki rg ad p}