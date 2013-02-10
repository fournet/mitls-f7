module Nonce

open Bytes

#if ideal
let log = ref []
#endif

open System

let mkRandom (i : int) : bytes = CoreRandom.random i
let dawn = new System.DateTime(1970, 1, 1)
let timestamp () = bytes_of_int 4 ((int32) (DateTime.UtcNow - dawn).TotalSeconds)


let rec mkHelloRandom(): bytes =
    let Cr = timestamp() @| mkRandom 28
    //#begin-idealization
    #if ideal
    if memr !log Cr then 
        mkHelloRandom () // we formally retry to exclude collisions.
    else 
        log := Cr::!log
        Cr
    #else //#end-idealization
    Cr
    #endif
