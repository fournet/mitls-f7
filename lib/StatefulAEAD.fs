module StatefulAEAD

open Bytes
open Error
open TLSInfo
open TLSKey

let encrypt (ki:KeyInfo) (ak:AEADKey) (iv:ENCKey.iv3) (r:DataStream.range)
    (ad:StatefulPlain.addData) (s:StatefulPlain.state) (f:StatefulPlain.fragment) = 
  let pl = AEADPlain.fragmentToPlain ki s ad r f in
  let iv',c = AEAD.encrypt ki ak iv r ad pl in
  let ns = StatefulPlain.addFragment ki s ad r f in
    iv',c,ns

let decrypt (ki:KeyInfo) (ak:AEADKey) (iv:ENCKey.iv3) (r:DataStream.range)
    (ad:StatefulPlain.addData) (s:StatefulPlain.state) (e:ENC.cipher) = 
  let res = AEAD.decrypt ki ak iv ad e in
    match res with
        Correct ((iv,r,pl)) -> 
          let f = AEADPlain.plainToFragment ki s ad r pl in
          let ns = StatefulPlain.addFragment ki s ad r f in
            Correct ((iv,f,ns))
      | Error (x,y) -> Error (x,y)
