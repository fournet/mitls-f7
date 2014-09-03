#light "off"

module DH

open Bytes
open DHGroup

type secret

val leak  : p -> g -> elt -> secret -> bytes
val coerce: p -> g -> elt -> bytes -> secret

//Restricting the interface to the minimum
//val gen_pp     : unit -> p * g * (option<q>)
//val default_pp : unit -> p * g * (option<q>)

//val genKey: p -> g -> option<q> -> elt * secret
//val exp: p -> g -> elt -> elt -> secret -> PMS.dhpms

val serverGen: unit -> p * g * elt * secret
val clientGenExp: p -> g -> elt -> (elt * secret * PMS.dhpms)
val serverExp: p -> g -> elt -> elt -> secret -> PMS.dhpms 
