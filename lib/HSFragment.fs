module HSFragment
open Bytes
open TLSInfo
open Range
open Error
open TLSError

type fragment = {frag: rbytes}
type stream = {sb:bytes list}
type plain = fragment

let userPlain (id:id) (r:range) b = {frag = b}
let userRepr  (id:id) (r:range) f = f.frag

let fragmentPlain (id:id) (r:range) b =
    if TLSExtensions.hasExtendedPadding id.ext then
        match TLSConstants.vlsplit 2 b with
        | Error(x,y) -> Error(x,y)
        | Correct(res) ->
            let (_,b) = res in
            correct ({frag = b})
    else
        correct ({frag = b})

let fragmentRepr (id:id) (r:range) f =
    let b = f.frag in
    if TLSExtensions.hasExtendedPadding id.ext then
        let r = alignedRange id r in
        let (_,h) = r in
        let plen = h - (length b) in
        let pad = createBytes plen 0 in
        let pad = TLSConstants.vlbytes 2 pad in
        pad @| b
    else
        b

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
