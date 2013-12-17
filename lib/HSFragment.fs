module HSFragment
open Bytes
open TLSInfo
open Range

type fragment = {frag: rbytes}
type stream = {sb:bytes list}
type plain = fragment

let fragmentPlain (ki:id) (r:range) b = {frag = b}
let fragmentRepr (ki:id) (r:range) f = f.frag

let init (e:id) = {sb=[]}
let extend (e:id) (s:stream) (r:range) (f:fragment) =
#if ideal
    {sb = f.frag :: s.sb}
#else
    s
#endif

let reStream (e:id) (s:stream) (r:range) (p:plain) (s':stream) = p

#if ideal
let widen (e:id) (r0:range) (r1:range) (f0:fragment) =
    let b = f0.frag in {frag = b}
#endif
