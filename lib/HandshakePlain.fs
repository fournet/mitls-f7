module HandshakePlain

open Bytes
open TLSInfo

let intToRange (i:int) = (i,i)
let rangeToInt (x:int,y:int) = y

type fragment = {b:bytes}
type stream = {s:bytes}
let emptyStream (ki:KeyInfo) = {s = [| |]}
let addFragment (ki:KeyInfo) (s:stream) (r:DataStream.range) (f:fragment) =  {s = s.s @| f.b}


let repr (ki:KeyInfo) (* (s:stream) (tlen:DataStream.range) *) f = f.b
let fragment (ki:KeyInfo) (s:stream) (tlen:DataStream.range) b = {b=b}
let makeFragment ki b =
    let (tl,f,r) = FragCommon.splitInFrag ki b in
    ((intToRange tl,{b=f}),r)

type ccsFragment = {ccsB:bytes}
let ccsRepr (ki:KeyInfo) (* (s:stream) (i:DataStream.range) *) f = f.ccsB
let ccsFragment (ki:KeyInfo) (s:stream) (i:DataStream.range)  b = {ccsB=b}

let addCCSFragment (ki:KeyInfo) (s:stream) (r:DataStream.range) (f:ccsFragment) =  {s = s.s @| f.ccsB}

let makeCCSFragment ki b =
    let (tl,f,r) = FragCommon.splitInFrag ki b in
    ((intToRange tl,{ccsB=f}),r)