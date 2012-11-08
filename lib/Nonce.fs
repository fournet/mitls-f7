module Nonce

open System
open Bytes

let epoch = new System.DateTime(1970, 1, 1)

let makeTimestamp () : int32 =
    (int32) (DateTime.UtcNow - epoch).TotalSeconds

let mkRandom (i : int) : bytes =
    CoreRandom.random i

// crypto abstraction? timing guarantees local disjointness (?)
let mkClientRandom () : bytes =
    let timeb = bytes_of_int 4 (makeTimestamp ()) in
    let rnd   = mkRandom 28 in
        timeb @| rnd
