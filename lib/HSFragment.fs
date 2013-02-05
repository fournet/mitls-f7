module HSFragment
open Bytes
open TLSInfo
open Range

type fragment = {frag: rbytes}
type stream = {sb:bytes list}
type plain = fragment

let fragmentPlain (ki:epoch) (r:range) b = {frag = b}
let fragmentRepr (ki:epoch) (r:range) f = f.frag

let init (e:epoch) = {sb=[]}
let extend (e:epoch) (s:stream) (r:range) (f:fragment) = {sb = f.frag :: s.sb}

let reStream (e:epoch) (s:stream) (r:range) (p:plain) (s':stream) = p

#if ideal
let widen (e:epoch) (r0:range) (r1:range) (f0:fragment) =
    let b = f0.frag in {frag = b}
#endif