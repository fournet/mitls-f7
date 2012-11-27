module HSFragment
open Bytes
open TLSInfo

type stream = {sb:bytes list}
type range = nat * nat

type fragment = {frag: stream * bytes}
type fpred = HSFragment of epoch * stream * range * bytes

let fragmentPlain (ki:epoch) (r:range) b =
    {frag = ({sb=[]},b)}
    
let fragmentRepr (ki:epoch) (r:range) f =
  let (s,d) = f.frag in
  d

let init (e:epoch) = {sb=[]}
let extend (e:epoch) (s:stream) (r:range) (f:fragment) =
    // FIXME ???
    // Fragment already embeds a stream!
    let (s,b) = f.frag in
    s