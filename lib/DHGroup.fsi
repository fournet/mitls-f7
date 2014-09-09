#light "off"

module DHGroup

open Bytes
open CoreKeys
open TLSError

type elt = bytes

#if ideal
val goodPP: dhparams -> bool
type preds = Elt of bytes * bytes * elt
#endif

val genElement  : dhparams -> elt
val checkParams : DHDB.dhdb -> nat -> bytes -> bytes -> Result<(DHDB.dhdb * dhparams)>
val checkElement: dhparams -> bytes -> option<elt>

val defaultDHparams: string -> DHDB.dhdb -> nat -> (DHDB.dhdb * dhparams)