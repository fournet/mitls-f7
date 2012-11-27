module StatefulPlain
open Bytes
open Error
open TLSConstants
open TLSInfo
open DataStream

type data = bytes

type prehistory = ( (* epoch * ContentType * TLSFragment.history * range * *) data * TLSFragment.fragment) list
type history = (nat * prehistory)

let makeAD ki ct =
    let si = epochSI(ki) in
    let pv = si.protocol_version in
    let bct  = ctBytes ct in
    let bver = versionBytes pv in
    if pv = SSL_3p0 
    then bct
    else bct @| bver

let parseAD e ad =
    let si = epochSI(e) in
    let pv = si.protocol_version in
    if pv = SSL_3p0 then
        match parseCT ad with
        | Error(x,y) -> unexpectedError "[parseAD] should never parse failing"
        | Correct(ct) -> ct
    else
        if length ad = 3 then
            let (bct, bver) = Bytes.split ad 1 in
            match parseCT bct with
            | Error(x,y) -> unexpectedError "[parseAD] should never parse failing"
            | Correct(ct) ->
                match parseVersion bver with
                | Error(x,y) -> unexpectedError "[parseAD] should never parse failing"
                | Correct(ver) ->
                    if pv <> ver then
                        unexpectedError "[parseAD] should never parse failing"
                    else ct
        else
            unexpectedError "[parseAD] should never parse failing"


type statefulPlain = {contents: TLSFragment.fragment}

let consHistory (ki:epoch) (h:prehistory) d f = (d,f)::h

let emptyHistory (ki:epoch): history = (0,[])
let addToHistory (ki:epoch) (sh:history) d (r:range) x = 
  let (seqn,h) = sh in
  let f = x.contents in
  let s' = seqn+1 in
  let nh = consHistory ki h d f in
  let res = (s',nh) in
  res

let statefulPlain (ki:epoch) (h:history) (ad:data) (r:range) (b:bytes) =
    let h = TLSFragment.emptyHistory ki // FIXME
    let ct = parseAD ki ad in
    {contents = TLSFragment.fragmentPlain ki ct h r b}
let statefulRepr (ki:epoch) (h:history) (ad:data) (r:range) (f:statefulPlain) =
    let h = TLSFragment.emptyHistory ki // FIXME
    let ct = parseAD ki ad in
    TLSFragment.fragmentRepr ki ct h r f.contents

let contents  (ki:epoch) (h:history) (ad:data) (rg:range) f = f.contents
let construct (ki:epoch) (h:history) (ad:data) (rg:range) c = {contents = c}

let TLSFragmentToFragment ki ct (ss:TLSFragment.history) st rg f =
  let ad = makeAD ki ct in
  construct ki st ad rg f

let fragmentToTLSFragment ki ct (ss:TLSFragment.history) st rg f =
  let ad = makeAD ki ct in
  contents ki st ad rg f
