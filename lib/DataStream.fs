module DataStream
open TLSInfo
open Bytes
open Error

type range = int * int (* length range *)
type rbytes = bytes 

let rangeSum (l0,h0) (l1,h1) =
  let l = l0 + l1
  let h = h0 + h1
  (l,h)
  
type stream = {sb: bytes}
type delta = {db: bytes}

let init (ki:KeyInfo) = {sb = [| |]}

let append (ki:KeyInfo) (s:stream) (r:range) (d:delta) = 
  {sb = s.sb @| d.db}

let split (ki:KeyInfo) (s:stream)  (r0:range) (r1:range) (d:delta) = 
  // we put as few bytes as we can in b0, 
  // to prevent early processing of split fragments
  let (l0,_) = r0
  let (_,h1) = r1
  let n = length d.db
  let n0 = if n <= l0 + h1 then l0 else n - h1 
  let (b0,b1) = Bytes.split d.db n0
  ({db = b0},{db = b1})

let join (ki:KeyInfo) (s:stream)  (r0:range) (d0:delta) (r1:range) (d1:delta) = 
  let r = rangeSum r0 r1 //CF: ghost computation to help Z3 
  {db = d0.db @| d1.db}
  
let delta (ki:KeyInfo) (s:stream) (r:range) (b:bytes) = {db = b}
let deltaRepr (ki:KeyInfo) (s:stream) (r:range) (d:delta) = d.db
