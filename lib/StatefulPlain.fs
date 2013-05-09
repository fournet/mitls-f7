module StatefulPlain
open Bytes
open Error
open TLSError
open TLSConstants
open TLSInfo
open Range

type cadata = cbytes
type adata = bytes

let makeAD (e:id) ct =
    let pv = pv_of_id e
    let bct  = ctBytes ct in
    let bver = versionBytes pv in
    if pv = SSL_3p0 
    then bct
    else bct @| bver

let parseAD (e:id) ad =
    let pv = pv_of_id e
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
let consHistory (e:id) (h:prehistory) (d:adata) (r:range) (f:fragment) =
#if ideal
    (d,r,f)::h
#else
    h
#endif

let emptyHistory (e:id): history = (0,[])
let extendHistory (e:id) d (sh:history) (r:range) f = 
  let (seqn,h) = sh in
  let s' = seqn+1 in
  let nh = consHistory e h d r f in
  let res = (s',nh) in
  res

let plain (e:id) (h:history) (ad:adata) (r:range) (b:bytes) =
    let h = TLSFragment.emptyHistory (idInv e) //CF Not Auth: we can pick any history
    let ct = parseAD e ad in
    {contents = TLSFragment.plain (idInv e) ct h r b}
let reprFragment (e:id) (ad:adata) (r:range) (f:plain) =
    let ct = parseAD e ad in
    let x = f.contents in
    TLSFragment.reprFragment (idInv e) ct r x
let repr e (h:history) ad r f = reprFragment e ad r f

#if ideal
let widen e ad r f =
    let ct = parseAD e ad in
    let f1 = TLSFragment.widen (idInv e) ct r f.contents in
    {contents = f1}
#endif

let RecordPlainToStAEPlain (e:id) (ct:ContentType) (ad:adata) (ss:TLSFragment.history) (st:history) (rg:range) f = {contents = f}
let StAEPlainToRecordPlain (e:id) (ct:ContentType) (ad:adata) (ss:TLSFragment.history) (st:history) (rg:range) f = f.contents
