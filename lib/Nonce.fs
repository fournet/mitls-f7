module Nonce

open Bytes

#if ideal
let log = ref []
#endif

open System

let timestamp () = bytes_of_int 4 (Date.secondsFromDawn ())


let rec mkHelloRandom(): bytes =
    let Cr = timestamp() @| random 28
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
