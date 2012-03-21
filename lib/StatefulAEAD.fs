module StatefulAEAD

open Bytes
open Error
open TLSInfo
open StatefulPlain
open DataStream

type prestate =
    { key: AEAD.AEADKey;
      seqn: nat;
      history: TLSFragment.history // ghost
    }

type state = prestate
type reader = state
type writer = state

let initState (ki:KeyInfo) key =
    { key = key
      seqn = 0
      history = TLSFragment.emptyHistory ki}

let history (ki:KeyInfo) s = s.history

type cipher = ENC.cipher

let encrypt (ki:KeyInfo) (w:writer) (ad0:data) (r:range) (f:fragment) =
  let h = addFragment ki w.history ad0 r f in
  let w = {w with history = h} in
  let pl = AEADPlain.fragmentToPlain ki (history ki w) ad0 r f in
  let ad = makeAD w.seqn ad0 in
  let key,c = AEAD.encrypt ki w.key ad r pl in
  let w = {w with key = key
                  seqn = w.seqn+1} in
  (w,c)

let decrypt (ki:KeyInfo) (r:reader) (ad0:data) (e:cipher) = 
  let ad = makeAD r.seqn ad0 in
  let res = AEAD.decrypt ki r.key ad e in
    match res with
      | Correct ((key,rg,pl)) ->
          let f = AEADPlain.plainToFragment ki (history ki r) ad0 rg pl in
          let h = addFragment ki r.history ad0 rg f in
          let r = {r with history = h
                          key = key
                          seqn = r.seqn+1}
          Correct ((r,rg,f))
      | Error (x,y) -> Error (x,y)
