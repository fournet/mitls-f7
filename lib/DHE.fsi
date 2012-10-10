module DHE

open Bytes
open TLSInfo

type g = bytes
type p = bytes
type x          // private DH part
type y = bytes  // public  DH part

type pms        // shared  DH key

val genParams: unit -> g * p
val genKey: g -> p -> x * y
val genPMS: SessionInfo -> g -> p -> x -> y -> pms

// AP: to be put in some DHEPlain module
val leak: SessionInfo -> pms -> bytes