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

// AP: to be put in some DHEPlain module. CF: no?
val leak: SessionInfo -> pms -> bytes
