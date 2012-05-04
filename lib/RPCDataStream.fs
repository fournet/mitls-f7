module RPCDataStream
open TLSInfo
open Bytes
open Error

let msglen = 2+128

type msg = bytes

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
    let si = epochSI(ki) in
    let padSize = CipherSuites.maxPadSize si.protocol_version si.cipher_suite in
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
        if h = 0 then
            ((l,h),(0,0))
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

type stream = { sb : bytes list }
type delta  = { contents : bytes }

let deltaPlain (ki:epoch) (s:stream) (r:range) (b:rbytes) = {contents = b}
let deltaRepr (ki:epoch) (s:stream) (r:range) (d:delta) = d.contents

type es = EmptyStream of epoch

let split (ki:epoch) (s:stream) (r0:range) (r1:range) (d:delta) = 
  let (l0, _ ) = r0
  let (_ , h1) = r1
  let n  = length d.contents
  let n0 = if n <= l0 + h1 then l0 else n - h1 
  let (sb0, sb1) = Bytes.split d.contents n0
  ({contents = sb0}, {contents = sb1})

let rec byteslst_to_bytes = fun ls ->
    match ls with
    | [] -> [||]
    | hd::tl -> (byteslst_to_bytes tl) @| hd

let stream_to_bytes = fun (ki:epoch) h ->
    byteslst_to_bytes h.sb

type pred = P of bytes * bytes * epoch * stream * bytes

let createRequest (ki:epoch) (s:stream) (r:range) (b:bytes) =
    Pi.expect (P([||], b, ki, s, b))
    {contents = b}
