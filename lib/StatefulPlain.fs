module StatefulPlain
open Error
open Bytes
open TLSInfo
open DataStream
open Formats
open TLSFragment

type data = bytes

type history =
    | Empty
    | ConsHistory of history * data * range * sbytes

let emptyHistory (ki:KeyInfo) = Empty
let addToHistory (ki:KeyInfo) h d r x = ConsHistory(h,d,r,x)

type fragment = sbytes

let parseAD ad = 
  let bs,ad' = Bytes.split ad 8 in
  let n = seq_of_bytes bs in 
    (n,ad')

let makeAD n ad =
  let bn = bytes_of_seq n in
    bn @| ad

let fragment (ki:KeyInfo) (h:TLSFragment.history) (ad:bytes) (r:range) (b:bytes) = plain ki r b

let repr (ki:KeyInfo) (h:TLSFragment.history) (ad:bytes) (r:range) (f:fragment) = repr ki r f

let TLSFragmentToFragment (ki:KeyInfo) (ct:ContentType) (h:history) (ss:TLSFragment.history) (rg:DataStream.range) (f:TLSFragment.fragment) =
    match f with
    | FHandshake(f) -> f
    | FAlert(f) -> f
    | FCCS(f) -> f
    | FAppData(f) -> f

let fragmentToTLSFragment (ki:KeyInfo) (ct:ContentType) (h:history) (ss:TLSFragment.history) (rg:range) (f:fragment) =
    match ct with
    | Handshake -> FHandshake(f)
    | Alert -> FAlert(f)
    | Change_cipher_spec -> FCCS(f)
    | Application_data -> FAppData(f)


