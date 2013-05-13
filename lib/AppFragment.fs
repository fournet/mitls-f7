module AppFragment
open Bytes
open TLSInfo
open Range
open DataStream

#if ideal
type fpred = DeltaFragment of epoch * stream * range * delta
#endif

type fragment = {frag: epoch * stream * delta}
type plain = fragment

let fragment e s r d = 
    let i = id e in
    let f = {frag = e,s,d} in
    #if ideal
    Pi.assume (DeltaFragment(e,s,r,d));
    #endif
    let s' = append e s r d in
    (f,s')

let delta e s r f = 
    let (e',s',d) = f.frag in
    #if ideal
    if auth e then
      // typechecking relies on proving that e = e' & s = s'. How? 
      let s'' = append e s r d in
      (d,s'')
    else
      // we coerce d to the local epoch 
      let raw = deltaRepr e' s' r d in
      let d' = deltaPlain e s r raw in
      let s'' = append e s r d' in
      (d',s'')
    #else
      // we could skip this append 
      let s'' = append e s r d in
      (d,s'')
    #endif

let plain i r b =
  let e = TLSInfo.unAuthIdInv i in
  let s = DataStream.init e in
  let d = DataStream.deltaPlain e s r b in
  {frag = (e,s,d)}

let repr (i:id) r f =
  let (e',s,d) = f.frag in
  DataStream.deltaRepr e' s r d

#if ideal
let widen (i:id) (r0:range) (f0:fragment) =
    let r1 = rangeClass i r0 in
    let (e,s,d0) = f0.frag in
    let d1 = DataStream.widen e s r0 r1 d0 in
    let (f1,_) = fragment e s r1 d1 in
    f1
#endif


   

(*KB unused
val delta': ki:epoch -> s:(;Id(ki)) stream -> r:range -> 
  f:(;Id(ki),r) fragment{not AuthId(ki)} -> 
  d:(;Id(ki),s,r) delta * s':(;Id(ki)) stream{s' = ExtendStreamDelta(Id(ki),s,r,d)}

let delta' e s r f = 
    let i = id e in
    let (s',d) = f.frag in
    let b = DataStream.deltaRepr i s' r d in
    let d = DataStream.deltaPlain i s r b in
    let s'' = append i s r d in 
    (d,s'')
*)

