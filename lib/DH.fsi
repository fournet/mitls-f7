#light "off"

module DH

open Bytes
open DHGroup

type secret

val leak  : p -> g -> elt -> secret -> bytes
val coerce: p -> g -> elt -> bytes -> secret

val serverGen: unit -> p * g * elt * secret
val clientGenExp: p -> g -> elt -> (elt * secret * PMS.dhpms)
val serverExp: p -> g -> elt -> elt -> secret -> PMS.dhpms 
