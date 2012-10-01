module RSAPlain
open Bytes
open TLSInfo

type repr = bytes
type pms = repr

let genPMS (id:SessionInfo) (vc:CipherSuites.ProtocolVersion) : pms = 
    let verBytes = CipherSuites.versionBytes vc in
    let rnd = mkRandom 46 in
    let pms = verBytes @| rnd in
    pms

failwith "tmp"
let coerce id x = x
let leak id x = x

