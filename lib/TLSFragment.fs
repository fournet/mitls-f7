module TLSFragment

open Error
open Bytes
open TLSInfo
open Formats
open CipherSuites

type fragment =
    | FHandshake of Handshake.fragment
    | FCCS of Handshake.ccsFragment
    | FAlert of Alert.fragment
    | FAppData of AppDataStream.fragment
and history = {
  handshake: Handshake.stream;
  alert: Alert.stream;
  ccs: Handshake.stream;
  appdata: AppDataStream.stream;
  log: (ContentType * history * DataStream.range * fragment) list;
}

type addData = bytes

let makeAD pv ct =
    let bct  = ctBytes ct in
    let bver = versionBytes pv in
    if pv = SSL_3p0 
    then bct
    else bct @| bver

let parseAD pv ad =
    if pv = SSL_3p0 then
      match parseCT ad with
        | Error(x,y) -> unexpectedError "[parseAD] should always be invoked on valid additional data"
        | Correct(ct) -> ct
    else
      let (ct1,bver) = split ad 1 in
        if bver <> versionBytes pv then
          unexpectedError "[parseAD] should always be invoked on valid additional data"
        else
          match parseCT ct1 with
            | Error(x,y) -> unexpectedError "[parseAD] should always be invoked on valid additional data"
            | Correct(ct) -> ct


let TLSFragmentRepr ki (tlen:DataStream.range) (seqn:int) (ct:ContentType) frag =
    match frag with
    | FHandshake(f) -> Handshake.repr ki tlen 0 f
    | FCCS(f) -> Handshake.ccsRepr ki tlen 0 f
    | FAlert(f) -> Alert.repr ki tlen 0 f
    | FAppData(f) -> AppDataStream.repr ki tlen 0 f

let TLSFragment ki (tlen:DataStream.range) seqn (ct:ContentType) b =
    match ct with
    | Handshake ->          FHandshake(Handshake.fragment ki tlen seqn b)
    | Change_cipher_spec -> FCCS(Handshake.ccsFragment ki tlen seqn b)
    | Alert ->              FAlert(Alert.fragment ki tlen seqn b)
    | Application_data ->   FAppData(AppDataStream.fragment ki tlen seqn b)

