module Fragment
open Bytes
open TLSInfo
open DataStream

type fragment = {frag: stream * delta}
type fpred = DeltaFragment of KeyInfo * stream * range * delta


let fragment ki s r d = 
  let f = {frag = s,d} in
    Pi.assume (DeltaFragment(ki,s,r,d));
    let s' = append ki s r d in
    f,s'

let delta ki s r f = 
  let (s',d) = f.frag in
  Pi.expect (F7.Equals(s,s'));
  let s'' = append ki s r d in 
    d,s''

let fragmentPlain ki r b =
  let s = DataStream.init ki in
  let d = DataStream.deltaPlain ki s r b in
    {frag = (s,d)}
    
let fragmentRepr ki r f =
  let (s,d) = f.frag in
    DataStream.deltaRepr ki s r d
