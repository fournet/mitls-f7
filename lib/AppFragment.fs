module AppFragment
open Bytes
open TLSInfo
open Range
open DataStream

type fragment = {frag: epoch * stream * delta}
#if verify
type fpred = DeltaFragment of epoch * stream * range * delta
#endif
type plain = fragment


let fragment ki s r d = 
    let i = id ki in
    let f = {frag = ki,s,d} in
#if verify
    Pi.assume (DeltaFragment(ki,s,r,d));
#endif
    let s' = append ki s r d in
    (f,s')

let delta ki s r f = 
    let (ki',s',d) = f.frag in
#if ideal
    let a = auth ki in
    if a then
#endif
        let s'' = append ki s r d in
        (d,s'')
#if ideal
    else
        let b = deltaRepr ki' s' r d in
        let d' = deltaPlain ki s r b in
        let s'' = append ki s r d' in
        (d',s'')
#endif

(*KB unused
let delta' ki s r f = 
    let i = id ki in
    let (s',d) = f.frag in
    let b = DataStream.deltaRepr i s' r d in
    let d = DataStream.deltaPlain i s r b in
    let s'' = append i s r d in 
    (d,s'')
*)

let plain i r b =
  let e = TLSInfo.unAuthIdInv i in
  let s = DataStream.init e in
  let d = DataStream.deltaPlain e s r b in
  {frag = (e,s,d)}

let repr (i:id) r f =
  let (ki',s,d) = f.frag in
  DataStream.deltaRepr ki' s r d

#if ideal
let widen (i:id) (r0:range) (f0:fragment) =
    let r1 = rangeClass i r0 in
    let (e,s,d0) = f0.frag in
    let d1 = DataStream.widen e s r0 r1 d0 in
    let (f1,_) = fragment e s r1 d1 in
    f1
#endif
