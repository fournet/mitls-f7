module MACPlain

open Bytes
open TLSInfo

type MACPlain = {p:bytes}
type addData = bytes

let MACPlain ki tlen ad f =
    let fB = TLSFragment.repr ki tlen f
    let fLen = bytes_of_int 2 (length fB) in
    let fullData = ad @| fLen in 
    {p = fullData @| fB}

let reprMACPlain (ki:KeyInfo) p = p.p

type MACed = {m:bytes}
let MACed (ki:KeyInfo) b = {m=b}
let reprMACed (ki:KeyInfo) m = m.m