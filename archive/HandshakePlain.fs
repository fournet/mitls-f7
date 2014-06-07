module HandshakePlain

open Bytes
open TLSInfo
open DataStream

let intToRange (i:int) = (i,i)
let rangeToInt (x:int,y:int) = y

type stream = DataStream.stream
type fragment = delta

let repr (ki:KeyInfo) (s:stream) (r:range) f = deltaRepr ki s r f
let fragment (ki:KeyInfo) (s:stream) (r:range) b = delta ki s r b
let makeFragment ki b =
    // FIXME: That's an hack. We seriously need to port this plain to DataStream
    let (tl,f,rem) = FragCommon.splitInFrag ki b in
    let s = DataStream.init ki in
    let d = DataStream.delta ki s (tl,tl) f in
    (((tl,tl),d),rem)

type ccsFragment = delta
let ccsRepr (ki:KeyInfo) (s:stream) (r:range) f = deltaRepr ki s r f
let ccsFragment (ki:KeyInfo) (s:stream) (r:range) b = delta ki s r b

let makeCCSFragment ki b =
    // FIXME: That's an hack. We seriously need to port this plain to DataStream
    let (tl,f,rem) = FragCommon.splitInFrag ki b in
    let s = DataStream.init ki in
    let d = DataStream.delta ki s (tl,tl) f in
    (((tl,tl),d),rem)