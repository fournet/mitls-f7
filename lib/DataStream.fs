module DataStream

open TLSInfo
open Bytes
open Error

let max_TLSPlaintext_fragment_length  = 16384 (* 2^14 *)
let max_TLSCompressed_fragment_length = max_TLSPlaintext_fragment_length + 1024
let max_TLSCipher_fragment_length     = max_TLSCompressed_fragment_length + 1024
let fragmentLength                    = max_TLSPlaintext_fragment_length

type range  = nat * nat (* length range *)
type rbytes = bytes 

let rangeSum (l0, h0) (l1, h1) =
  let l = l0 + l1 in
  let h = h0 + h1 in
      (l, h)

let splitRange (ki:epoch) (r:range) =
    let (l, h) = r in
        if h > max_TLSPlaintext_fragment_length then
            Error.unexpectedError "PwDataStream.splitRange: h-range > max-fragment-size"
        else
            (r, (0, 0))

type stream = { sb: bytes list }
type delta  = { contents: rbytes }

let createDelta (ki:epoch) (s:stream) (r:range) (b:bytes) =
    { contents = b }

let deltaPlain (ki:epoch) (s:stream) (r:range) (b:rbytes) = { contents = b }
let deltaRepr  (ki:epoch) (s:stream) (r:range) (d:delta)  = d.contents

type es = EmptyStream of epoch

let init (ki:epoch) = { sb = [] }

let append (ki:epoch) (s:stream) (r:range) (d:delta) = 
  { sb = d.contents :: s.sb }

let split (ki:epoch) (s:stream) (r0:range) (r1:range) (d:delta) : delta * delta = 
    Error.unexpectedError "[PwDataStream.split]: fragmentation not allowed"
