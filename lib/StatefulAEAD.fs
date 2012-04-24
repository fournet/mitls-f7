module StatefulAEAD

// implemented using AEAD with a sequence number 

open Bytes
open Error
open TLSInfo
open StatefulPlain
open DataStream

type prestate =
    { key: AEAD.AEADKey; 
      history: history   
    }

type state = prestate
type reader = state
type writer = state

let GEN ki =
    let r,w = AEAD.GEN ki in
    let h = emptyHistory ki in
    ( { key = r; history = h},
      { key = w; history = h})  
let COERCE ki b =
    let k  = AEAD.COERCE ki b in
    let h = emptyHistory ki in
    { key = k; history = h}
let LEAK ki s = AEAD.LEAK ki s.key

let history (ki:epoch) s = s.history

type cipher = AEAD.cipher

let encrypt (ki:epoch) (w:writer) (ad0:data) (r:range) (f:fragment) =
  let h = w.history in
  let p = FragmentToAEADPlain ki h ad0 r f in
  let ad = makeAD ki h ad0 in
  let k,c = AEAD.encrypt ki w.key ad r p in
  let h = addToHistory ki h ad0 r f in
  let w = {key = k; history = h} in
  (w,c)

let decrypt (ki:epoch) (r:reader) (ad0:data) (e:cipher) =
  let h = r.history in
  let ad = makeAD ki h ad0 in
  let res = AEAD.decrypt ki r.key ad e in
  match res with
    | Correct x ->
          let (k,rg,p) = x in
          let f = AEADPlainToFragment ki h ad0 rg p in
          let h = addToHistory ki h ad0 rg f in
          correct (({history = h; key = k},rg,f))
    | Error (x,y) -> Error (x,y)
