module RSAPlain
open Bytes
open TLSInfo

type repr = bytes
type pms = {pmsbytes: repr}

let genPMS (id:SessionInfo) (vc:CipherSuites.ProtocolVersion) : pms = 
    let verBytes = CipherSuites.versionBytes vc in
    let rnd = mkRandom 46 in
    let pms = verBytes @| rnd in
    {pmsbytes = pms}

let coerce id b = {pmsbytes = b}
let leak id pms = pms.pmsbytes

