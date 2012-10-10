module DHE

open Bytes
open TLSInfo

type g = bytes
type p = bytes
type x = {x:bytes}
type y = bytes
type pms = {pms:bytes}

let genParams () : g * p = failwith "TODO"
let genKey (g:g) (p:p) : x * y = failwith "TODO"
let genPMS (si:SessionInfo) (g:g) (p:p) (x:x) (y:y) : pms = failwith "TODO"
let leak (si:SessionInfo) pms = pms.pms