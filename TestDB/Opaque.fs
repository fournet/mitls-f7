module Opaque

open Bytes

open Newtonsoft.Json

//[<CLIMutable>]
//type opaque_record = { value:bytes }

// let v = { repr = CoreRandom.random(64) }

type opaque = Value of bytes
  
let v = Value (CoreRandom.random(64))

//let show (v:opaque) = match v with | V s -> sprintf "V %A" (cbytes s)
//
//let equal v w = 
//    match v, w with
//    | V s, V t -> s.Equals(t)
