module AppDataPlain

open Bytes
open TLSInfo
open FragCommon


type lengths = int list (* a list of desired ciphertext lengths *)

type appdata = {appD:bytes}

// interface to AppData module
let length (si:SessionInfo) ad = length ad.appD

let rec estimateLengths sinfo len =
    if len > fragmentLength then 
        cipherLength sinfo fragmentLength :: 
        estimateLengths sinfo (len - fragmentLength) 
    else 
        [cipherLength sinfo len]

let empty_appdata (si:SessionInfo) = {appD = [||]}
let is_empty_appdata (si:SessionInfo) data = (equalBytes data.appD [||])

// interface to top level app
let appdata (si:SessionInfo) (lens:lengths) data = {appD = data}
let appdataBytes (si:SessionInfo) data = data.appD

type fragment = {b:bytes}

let concat_fragment_appdata (ki:KeyInfo) (tlen:int) (seqn:int) data lens (appdata:appdata) :(lengths * appdata) =
    (* TODO: If ki says so, first decompress data, then append it *)
    let resData = { appD = appdata.appD @| data.b} in
    // we may need a special @ for getting our precise refinement 
    let reslengths = lens @ [tlen] in
    (reslengths,resData)

let app_fragment (ki:KeyInfo) (seqn:int) lens (appdata:appdata) : ((int * fragment) * (lengths * appdata)) =
    (* The idea is: Given the cipertext target length, we get a *smaller* plaintext fragment
       (so that MAC and padding can be added back).
       In practice: since estimateLengths acts deterministically on the appdata length, we do the same here, and
       we rely on the fact that the implementation here is the same in estimateLenghts, so that our fragment size is
       always aligned with the estimated ones.
       TODO: we should also perform compression *now*. After we extract the next fragment from appdata, we compress it
       and only after we return it. The target length will be compatible with the compressed length, because the
       estimateLengths function takes compression into account. *)
    match lens with
    | thisLen::remLens ->
        (* Same implementation as estimateLengths, but one fragment at a time *)
        if (Bytes.length appdata.appD) > fragmentLength then
            (* get one full fragment of appdata *)
            (* TODO: apply compression on thisData *)
            let (thisData,remData) = split appdata.appD fragmentLength in
            ((thisLen,{b = thisData}),(remLens,{appD = remData}))
        else
            (* consume all the remaining appdata. assert remLens is the empty list *)
            ((thisLen,{b = appdata.appD}), (remLens,{appD = [||]}))
    | [] -> ((0,{b = [||]}),(lens,appdata))

let repr (ki:KeyInfo) (i:int) (seqn:int) f = f.b
let fragment (ki:KeyInfo) (i:int) (seqn:int) b = {b=b}

let reIndex (oldSI:SessionInfo) (newSI:SessionInfo) (appd:appdata) = appd
let reIndexLengths (oldSI:SessionInfo) (newSI:SessionInfo) (l:lengths) = l