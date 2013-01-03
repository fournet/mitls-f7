module StatefulAEAD

// implemented using AEAD with a sequence number 

open Bytes
open Error
open TLSInfo
open StatefulPlain

type prestate = { 
  key: AEAD.AEADKey; 
  history: history   
}

type state = prestate
type reader = state
type writer = state

let GEN ki =
  let w,r = AEAD.GEN ki in
  let h = emptyHistory ki in
  ( { key = w; history = h},
    { key = r; history = h})  
let COERCE ki b =
  let k  = AEAD.COERCE ki b in
  let h = emptyHistory ki in
  { key = k; history = h}
let LEAK ki s = AEAD.LEAK ki s.key

let history (ki:epoch) s = s.history

type cipher = AEAD.cipher

let encrypt (ki:epoch) (w:writer) (ad0:adata) (r:range) (f:plain) =
  let h = w.history in
  let p = AEADPlain.StatefulPlainToAEADPlain ki h ad0 r f in
  let ad = AEADPlain.makeAD ki h ad0 in
  let k,c = AEAD.encrypt ki w.key ad r p in
  let h = addToHistory ki ad0 h r f in
  let w = {key = k; history = h} in
  (w,c)

let decrypt (ki:epoch) (r:reader) (ad0:adata) (e:cipher) =
  let h = r.history in
  let ad = AEADPlain.makeAD ki h ad0 in
  let res = AEAD.decrypt ki r.key ad e in
  match res with
    | Correct x ->
          let (k,rg,p) = x in
          let f = AEADPlain.AEADPlainToStatefulPlain ki h ad0 rg p in
          let h = addToHistory ki ad0 h rg f in
          correct (({history = h; key = k},rg,f))
    | Error (x,y) -> Error (x,y)
