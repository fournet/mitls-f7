module DHGroup

open Bytes

type p = bytes
type elt = bytes
type g = elt
type secret

val genKey: p -> g -> elt * secret
val leak: p -> g -> elt -> secret -> bytes