module Opaque

open Bytes

type opaque = { value:bytes; more:bool }

let v = { value = CoreRandom.random(2); more = true }

let show (v:opaque) = match v with | { value = s; more = t } -> sprintf "{%A %A}" (cbytes s) t

//type opaque = Value of bytes * bool
//  
//let v = Value (CoreRandom.random(2),true)
//
//let show (v:opaque) = match v with | Value (s, t) -> sprintf "Value %A %b" (cbytes s) t

//
//let equal v w = 
//    match v, w with
//    | V s, V t -> s.Equals(t)
