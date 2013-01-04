module HSFragment
open Bytes
open TLSInfo

type fragment = {frag: rbytes}
type stream = {sb:bytes list}
type plain = fragment

let fragmentPlain (ki:epoch) (r:range) b = {frag = b}
let fragmentRepr (ki:epoch) (r:range) f = f.frag

let init (e:epoch) = {sb=[]}
let extend (e:epoch) (s:stream) (r:range) (f:fragment) = {sb = f.frag :: s.sb}