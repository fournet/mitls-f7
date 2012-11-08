module DH

open Bytes
open DHGroup

type secret

val gen_pp     : unit -> p * g
val default_pp : unit -> p * g

val genKey: p -> g -> elt * secret
val exp: p -> g -> elt -> elt -> secret -> CRE.dhpms