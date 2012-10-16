module DHE

open Bytes
open TLSInfo

type g = bytes
type p = bytes

type dhparams = g * p

type x          // private DH part
type y = bytes  // public  DH part

type pms        // shared  DH key

val genParams     : unit -> dhparams
val defaultParams : unit -> dhparams
val genKey        : dhparams -> x * y
val genPMS        : SessionInfo -> dhparams -> x -> y -> pms


// AP: to be put in some DHEPlain module
val leak: SessionInfo -> pms -> bytes
