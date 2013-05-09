module AppFragment
open Bytes
open TLSInfo
open Range
open DataStream

type fragment = {frag: stream * delta}
#if verify
type fpred = DeltaFragment of epoch * stream * range * delta
#endif
type plain = fragment


let fragment ki s r d = 
    let f = {frag = s,d} in
#if verify
    Pi.assume (DeltaFragment(ki,s,r,d));
#endif
    let s' = append ki s r d in
    (f,s')

let delta ki s r f = 
    let (s',d) = f.frag in
#if ideal
    if auth ki then
#endif
        let s'' = append ki s r d in
        (d,s'')
#if ideal
    else
        let b = deltaRepr ki s' r d in
        let d' = deltaPlain ki s r b in
        let s'' = append ki s r d' in
        (d',s'')
#endif

let delta' ki s r f = 
    let (s',d) = f.frag in
    let b = DataStream.deltaRepr ki s' r d in
    let d = DataStream.deltaPlain ki s r b in
    let s'' = append ki s r d in 
    (d,s'')

let plain ki r b =
  let s = DataStream.init ki in
  let d = DataStream.deltaPlain ki s r b in
  {frag = (s,d)}

let repr ki r f =
  let (s,d) = f.frag in
  DataStream.deltaRepr ki s r d

#if ideal
let widen (e:epoch) (r0:range) (f0:fragment) =
    let r1 = rangeClass (id e) r0 in
    let (s,d0) = f0.frag in
    let d1 = DataStream.widen e s r0 r1 d0 in
    let (f1,_) = fragment e s r1 d1 in
    f1
#endif