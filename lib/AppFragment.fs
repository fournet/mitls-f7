module AppFragment
open Bytes
open TLSInfo
open DataStream

type fragment = {frag: stream * delta}
type fpred = DeltaFragment of epoch * stream * range * delta
type plain = fragment


let fragment ki s r d = 
    let f = {frag = s,d} in
#if verify
    Pi.assume (DeltaFragment(ki,s,r,d));
#endif
    let s' = append ki s r d in
    f,s'

let delta ki s r f = 
  let (s',d) = f.frag in
  let s'' = append ki s r d in 
    d,s''

let delta' ki s r f = 
  let (s',d) = f.frag in
  let b = DataStream.deltaRepr ki s' r d in
  let d = DataStream.deltaPlain ki s r b in
  let s'' = append ki s r d in 
    d,s''

let plain ki r b =
  let s = DataStream.init ki in
  let d = DataStream.deltaPlain ki s r b in
  {frag = (s,d)}

let repr ki r f =
  let (s,d) = f.frag in
  DataStream.deltaRepr ki s r d
