module Nonce

open System
open Bytes

#if ideal
let log = ref []
#endif

let mkRandom (i : int) : bytes = CoreRandom.random i

let dawn = new System.DateTime(1970, 1, 1)
let timestamp () = bytes_of_int 4 ((int32) (DateTime.UtcNow - dawn).TotalSeconds)

let rec mkHelloRandom(): bytes =
    let Cr = timestamp() @| mkRandom 28
    #if ideal
    if memr Cr !log 
      then mkHelloRandom () // we retry; we could also raise a "bad" flag
      else log := Cr::!log
    #endif
    Cr