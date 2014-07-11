module Nonce

open Bytes
open Error

let timestamp () = bytes_of_int 4 (Date.secondsFromDawn ())

let random (n:nat) = 
  let r = CoreRandom.random n in
  let l = length r in
  if l = n then r 
  else unexpected "CoreRandom.random returned incorrect number of bytes"


let noCsr = random 64 // a constant value, with negligible probability of being sampled, excluded by idealization

#if ideal
let log = ref []
#endif

let rec mkHelloRandom(): bytes =
    let Cr = timestamp() in
    //#begin-idealization
    #if ideal
    if List.memr !log Cr then 
        mkHelloRandom () // we formally retry to exclude collisions.
    else 
        log := Cr::!log
        Cr
    #else //#end-idealization
    Cr
    #endif
