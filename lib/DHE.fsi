module DHE

open Bytes
open TLSInfo

type p = bytes
type elt = bytes
type g = elt
type pp = p * g

type x         
type y = elt 
type pms 

val gen_pp     : unit -> pp
val default_pp : unit -> pp
val genKey     : p -> g -> x * y
val genPMS     : SessionInfo -> p -> g -> x -> y -> pms

// AP: to be put in some DHEPlain module. CF: no?
val leak: SessionInfo -> pms -> bytes
