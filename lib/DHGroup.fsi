#light "off"

module DHGroup

open Bytes
open CoreKeys
open TLSError

type elt = bytes

val goodPP: dhparams -> bool

val genElement  : dhparams -> elt
val checkParams : DHDB.dhdb -> bytes -> bytes -> Result<(DHDB.dhdb * dhparams)>
val checkElement: dhparams -> bytes -> option<elt>

val defaultDHparams: string -> DHDB.dhdb -> (DHDB.dhdb * dhparams)