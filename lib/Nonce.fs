module Nonce

open Bytes

#if ideal
//MK this behavious seems to deserve a comment. What is going on here?
let log = ref []
let mkRandom (i: int) : bytes = failwith "specification only" 
let timestamp()       : bytes = failwith "specification only"

#else
open System

let mkRandom (i : int) : bytes = CoreRandom.random i

let dawn = new System.DateTime(1970, 1, 1)
let timestamp () = bytes_of_int 4 ((int32) (DateTime.UtcNow - dawn).TotalSeconds)
#endif


let rec mkHelloRandom(): bytes =
    let Cr = timestamp() @| mkRandom 28
    #if ideal
    if memr !log Cr then 
        mkHelloRandom () // we retry to prevent collision; we could also raise a "bad" flag
    else 
        log := Cr::!log
        Cr
    #else
    Cr
    #endif