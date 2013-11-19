module AppFragment
open Bytes
open TLSInfo
open Range
open DataStream
open Error
open TLSError

#if ideal
type fpred = DeltaFragment of epoch * stream * range * delta
#endif

type preFragment = {frag: epoch * stream * delta}
type fragment = preFragment
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
    //MK the following idealization is for reindexing. 
    //MK if auth, then we can use the e' indexed d, and are guaranteed that s=s'
    #if ideal
    if auth e then
      // typechecking relies on proving that e = e' & s = s'. How? 
      let s'' = append e s r d in
      (d,s'')
    else       
      // we coerce d to the local epoch
      //MK this requires that e' is not(Auth(e'))
      //MK this might be the case because we only use unAuthIdInv e' for not(Auth(e))
      //MK but could be hard to prove 
      //MK this breaks typing as f.frag != (e',s',d')
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
  if TLSExtensions.hasExtendedPadding i.ext then
      match TLSConstants.vlsplit 2 b with
      | Error(x,y) -> Error(x,y)
      | Correct(res) ->
        let (_,b) = res in
        let d = DataStream.deltaPlain e s r b in
        let res = {frag = (e,s,d)} in
        correct (res)
  else
      let d = DataStream.deltaPlain e s r b in
      let res = {frag = (e,s,d)} in
      correct (res)

let repr (i:id) r f =
  let (e',s,d) = f.frag in
  let b = DataStream.deltaRepr e' s r d in
  if TLSExtensions.hasExtendedPadding i.ext then
    let r = alignedRange i r in
    let (_,h) = r in
    let plen = h - (length b) in
    let pad = createBytes plen 0 in
    let pad = TLSConstants.vlbytes 2 pad in
    pad @| b
  else
    b

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

