#light "off"

module DH

open Bytes
open DHGroup

open CoreKeys
open CommonDH

val leak  : parameters -> element -> secret -> bytes
val coerce: parameters -> element -> bytes -> secret

val serverGenDH: string -> DHDB.dhdb -> nat * nat -> DHDB.dhdb * parameters * element * secret
val serverGenECDH: ECGroup.ec_curve -> parameters * element * secret

val clientGenExp: parameters -> element -> (element * PMS.dhpms)
val serverExp: parameters -> element -> element -> secret -> PMS.dhpms 

val serialize: element -> bytes
