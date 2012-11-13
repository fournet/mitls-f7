module Nonce

open System
open Bytes

let epoch = new System.DateTime(1970, 1, 1)

#if ideal
let log = ref []
#endif

let makeTimestamp () : int32 =
    (int32) (DateTime.UtcNow - epoch).TotalSeconds

let mkRandom (i : int) : bytes =
    CoreRandom.random i

// crypto abstraction? timing guarantees local disjointness (?)
#if ideal 
let rec mkHelloRandom () : bytes =
#else
let mkHelloRandom () : bytes =
#endif
    let timeb = bytes_of_int 4 (makeTimestamp ()) in
    let rnd   = mkRandom 28 in
    let Cr = timeb @| rnd
    #if ideal
    if (exists (fun el -> el=Cr) !log) then
        mkHelloRandom () //abort? Sample from smaller domain?
    else
        log := Cr::!log;
        Cr      
    #else
    Cr
    #endif

//do we have a similar function for ServerRandom? 
//Are they jointly unique, or only individually unique after idealization?