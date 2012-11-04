module DHE

open Bytes
open TLSInfo

type p = bytes
type elt = bytes
type g = elt

type secret 
type pms 

val gen_pp     : unit -> p * g
val default_pp : unit -> p * g
val genKey     : p -> g -> elt * secret
val exp        : p -> g -> elt -> elt -> secret -> pms
val sample     : p -> g -> elt -> elt           -> pms

val leak: p -> g -> elt -> elt -> pms -> bytes
