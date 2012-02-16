module StatefulAEAD

open Bytes
open Error
open TLSInfo
open TLSKey
open StatefulPlain
open DataStream

type cipher = ENC.cipher


let encrypt (ki:KeyInfo) (w:writer) (ad:data) (r:range) (f:fragment) = 
  let k = getKey ki w in
  let iv = getIV ki w in
  let seq = sequenceNo ki w in
  let ad = makeAD seq ad in
  let pl = AEADPlain.fragmentToPlain ki w ad r f in
  let iv',c = AEAD.encrypt ki k iv ad r pl in
  let w = addFragment ki w ad r f in
  let w = updateIV ki w iv' in
    w,c

let decrypt (ki:KeyInfo) (r:reader) (ad:data) (e:cipher) = 
  let seq = sequenceNo ki r in
  let ad = makeAD seq ad in
  let k = getKey ki r in
  let iv = getIV ki r in
  let res = AEAD.decrypt ki k iv ad e in
    match res with
        Correct ((iv,rg,pl)) -> 
          let f = AEADPlain.plainToFragment ki r ad rg pl in
          let r = addFragment ki r ad rg f in
          let r = updateIV ki r iv in
            Correct ((r,rg,f))
      | Error (x,y) -> Error (x,y)
