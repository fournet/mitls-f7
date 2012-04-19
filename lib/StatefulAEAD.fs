module StatefulAEAD

open Bytes
open Error
open TLSInfo
open StatefulPlain
open DataStream

type prestate =
    { key: AEAD.AEADKey;
      history: history // Sequence number + ghost refinement
    }

type state = prestate
type reader = state
type writer = state

let GEN ki =
    let r,w = AEAD.GEN ki in
    let eh = emptyHistory ki in
    ( { key = r; history = eh},
      { key = w; history = eh})  
let COERCE ki b =
    let key = AEAD.COERCE ki b in
    let eh = emptyHistory ki in
    { key = key;
      history = eh}
let LEAK ki s =
    AEAD.LEAK ki s.key

let history (ki:epoch) s = s.history

type cipher = ENC.cipher

let encrypt (ki:epoch) (w:writer) (ad0:data) (r:range) (f:fragment) =
  let h = w.history in
  let pl = FragmentToAEADPlain ki h ad0 r f in
  let ad = makeAD ki h ad0 in
  let key,c = AEAD.encrypt ki w.key ad r pl in
  let h = addToHistory ki h ad0 r f in
  let w = {key = key;
           history = h} in
  (w,c)

let decrypt (ki:epoch) (r:reader) (ad0:data) (e:cipher) =
  let h = r.history in
  let ad = makeAD ki h ad0 in
  let res = AEAD.decrypt ki r.key ad e in
    match res with
      | Correct res ->
          let (key,yy,pl) = res in
          let f = AEADPlainToFragment ki h ad0 yy pl in
          let h = addToHistory ki h ad0 yy f in
          let r = {history = h;
                   key = key} in
          correct (r,yy,f) 
      | Error (x,y) -> Error (x,y)
