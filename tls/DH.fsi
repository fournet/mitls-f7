#light "off"

module DH

open Bytes
open DHGroup

open CoreKeys

type secret

val leak  : dhparams -> elt -> secret -> bytes
val coerce: dhparams -> elt -> bytes -> secret

val serverGen: string -> DHDB.dhdb -> nat * nat -> DHDB.dhdb * dhparams * elt * secret
val clientGenExp: dhparams -> elt -> (elt * PMS.dhpms)
val serverExp: dhparams -> elt -> elt -> secret -> PMS.dhpms 
