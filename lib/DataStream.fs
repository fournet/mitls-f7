module DataStream
open TLSInfo
open Bytes
open Error

type range = int * int (* length range *)

type stream = {sb: bytes}
type delta = {db: bytes}

let init (ki:KeyInfo) = {sb = [| |]}

let append (ki:KeyInfo) (s:stream) (r:range) (d:delta) = 
  {sb = s.sb @| d.db}

let split (ki:KeyInfo) (s:stream)  (r:range) (r':range) (d:delta) = 
  let (min,max) = r in
  let (b0,b1) = Bytes.split d.db min in
    ({db = b0},
     {db = b1})

let delta (ki:KeyInfo) (s:stream) (r:range) (b:bytes) = {db = b}
let deltaRepr (ki:KeyInfo) (s:stream) (r:range) (d:delta) = d.db
