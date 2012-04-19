module DataStream
open TLSInfo
open Bytes
open Error

let max_TLSPlaintext_fragment_length = 16384 (* 2^14 *)
let max_TLSCompressed_fragment_length = max_TLSPlaintext_fragment_length + 1024
let max_TLSCipher_fragment_length = max_TLSCompressed_fragment_length + 1024
let fragmentLength = max_TLSPlaintext_fragment_length (* use e.g. 1 for testing *)

type range = nat * nat (* length range *)
type rbytes = bytes 

let rangeSum (l0,h0) (l1,h1) =
  let l = l0 + l1
  let h = h0 + h1
  (l,h)

let min (a:nat) (b:nat) =
    if a <= b then a else b
let max (a:nat) (b:nat) =
    if a >= b then a else b

let splitRange ki r =
    let (l,h) = r in
    let padSize = CipherSuites.maxPadSize ki.sinfo.protocol_version ki.sinfo.cipher_suite in
    if padSize = 0 then
        if l <> h then
            unexpectedError "[splitRange] invalid argument"
        else
            let length = min l fragmentLength in
            let rem = l-length in
            let r0 = (length,length) in
            let r1 = (rem,rem)
            (r0,r1)
    else
        let minpack = (h-l) / padSize
        let minfrag = (h-1) / fragmentLength
        let savebytes = max minpack minfrag
        let smallL = max (min (l-savebytes) fragmentLength) 0
        let smallH = min (min (padSize+smallL) fragmentLength) h
        let lsub = l - smallL in
        let hsub = h - smallH in
        if ((lsub > hsub)) then
            unexpectedError "Should not be possible, ask Alfredo" 
        else
          ((smallL,smallH),
           (lsub,hsub))

type stream = {sb: bytes list}
type delta = {contents: rbytes}

let createDelta (ki:KeyInfo) (s:stream) (r:range) (b:bytes) =
    {contents = b}

let deltaPlain (ki:KeyInfo) (s:stream) (r:range) (b:rbytes) = {contents = b}
let deltaRepr (ki:KeyInfo) (s:stream) (r:range) (d:delta) = d.contents

// ghost
type es = EmptyStream of KeyInfo

let init (ki:KeyInfo) = {sb = []}

let append (ki:KeyInfo) (s:stream) (r:range) (d:delta) = 
  {sb = d.contents :: s.sb}

let split (ki:KeyInfo) (s:stream)  (r0:range) (r1:range) (d:delta) = 
  // we put as few bytes as we can in b0, 
  // to prevent early processing of split fragments
  let (l0,_) = r0
  let (_,h1) = r1
  let n = length d.contents
  let n0 = if n <= l0 + h1 then l0 else n - h1 
  let (sb0,sb1) = Bytes.split d.contents n0
  ({contents = sb0},{contents = sb1})

let join (ki:KeyInfo) (s:stream)  (r0:range) (d0:delta) (r1:range) (d1:delta) = 
  let r = rangeSum r0 r1 //CF: ghost computation to help Z3 
  let sb = d0.contents @| d1.contents in
  {contents = sb}

