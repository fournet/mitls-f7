module DH

open Bytes
open DHGroup

val gen_pp     : unit -> p * g
val default_pp : unit -> p * g

val exp: p -> g -> elt -> elt -> secret -> CRE.dhpms