module StatefulPlain
open Bytes
open Error
open TLSError
open TLSConstants
open TLSInfo
open Range

type cadata = cbytes
type adata = bytes

let makeAD e ct =
    let si = epochSI(e) in
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
        | Error x -> unexpected "[parseAD] should never parse failing"
        | Correct(ct) -> ct
    else
        if length ad = 3 then
            let (bct, bver) = Bytes.split ad 1 in
            match parseCT bct with
            | Error x -> unexpected "[parseAD] should never parse failing"
            | Correct(ct) ->
                match parseVersion bver with
                | Error x -> unexpected "[parseAD] should never parse failing"
                | Correct(ver) ->
                    if pv <> ver then
                        unexpected "[parseAD] should never parse failing"
                    else ct
        else
            unexpected "[parseAD] should never parse failing"

type fragment = {contents: TLSFragment.fragment}

type prehistory = (adata * range * fragment) list
type history = (nat * prehistory)

type plain = fragment

//CF just for performance? justified because the history is ghost.
let consHistory (e:epoch) (h:prehistory) (d:adata) (r:range) (f:fragment) =
#if ideal
    (d,r,f)::h
#else
    h
#endif

let emptyHistory (e:epoch): history = (0,[])
let extendHistory (e:epoch) d (sh:history) (r:range) f = 
  let (seqn,h) = sh in
  let s' = seqn+1 in
  let nh = consHistory e h d r f in
  let res = (s',nh) in
  res

let plain (e:epoch) (h:history) (ad:adata) (r:range) (b:bytes) =
    let h = TLSFragment.emptyHistory e //CF Not Auth: we can pick any history
    let ct = parseAD e ad in
    {contents = TLSFragment.plain e ct h r b}
let reprFragment (e:epoch) (ad:adata) (r:range) (f:plain) =
    let ct = parseAD e ad in
    let x = f.contents in
    TLSFragment.reprFragment e ct r x
let repr e (h:history) ad r f = reprFragment e ad r f

#if ideal
let widen e ad r f =
    let ct = parseAD e ad in
    let f1 = TLSFragment.widen e ct r f.contents in
    {contents = f1}
#endif

let RecordPlainToStAEPlain (e:epoch) (ct:ContentType) (ad:adata) (ss:TLSFragment.history) (st:history) (rg:range) f = {contents = f}
let StAEPlainToRecordPlain (e:epoch) (ct:ContentType) (ad:adata) (ss:TLSFragment.history) (st:history) (rg:range) f = f.contents
