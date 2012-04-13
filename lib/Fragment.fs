module Fragment
open Error
open TLSInfo
open DataStream
type fragment = {frag: stream * delta}
type fpred = FragmentDelta of KeyInfo * stream * range * fragment
let fragment ki s r d = 
  let f = {frag = s,d} in
    Pi.assume (FragmentDelta(ki,s,r,f));
    let s' = append ki s r d in
    f,s'

let delta ki s r f = 
  let (s',d) = f.frag in
  if s = s' then 
    let s'' = append ki s r d in 
      d,s''
  else unexpectedError "expected a correct fragment delta for this stream"
