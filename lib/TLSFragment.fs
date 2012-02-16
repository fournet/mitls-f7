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
  log: fragmentSequence
}
and fragmentSequence = (ContentType * history * DataStream.range * fragment) list

let emptyHistory ki = {
  handshake = Handshake.emptyStream ki;
  alert = Alert.emptyStream ki;
  ccs = Handshake.emptyStream ki;
  appdata = AppDataStream.emptyStream ki;
  log = []
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


let TLSFragmentRepr ki (ct:ContentType) (h:history) (rg:DataStream.range) frag =
    match frag with
    | FHandshake(f) -> Handshake.repr ki h.handshake rg f
    | FCCS(f) -> Handshake.ccsRepr ki h.ccs rg f
    | FAlert(f) -> Alert.repr ki h.alert rg f
    | FAppData(f) -> AppDataStream.repr ki h.appdata rg f

let TLSFragment ki (ct:ContentType) (h:history) (rg:DataStream.range) b = 
    match ct with
    | Handshake ->          FHandshake(Handshake.fragment ki h.handshake rg b)
    | Change_cipher_spec -> FCCS(Handshake.ccsFragment ki h.ccs rg b)
    | Alert ->              FAlert(Alert.fragment ki h.alert rg b)
    | Application_data ->   FAppData(AppDataStream.fragment ki h.appdata rg b)

let addFragment ki ct h r f = 
  let nfs = (ct,h,r,f)::h.log in
  match ct,f with
    | Handshake,FHandshake f -> {h with log = nfs; 
                                        handshake = Handshake.addFragment ki h.handshake r f}
    | Change_cipher_spec,FCCS f -> {h with log = nfs; 
                                           ccs = Handshake.addCCSFragment ki h.ccs r f}
    | Alert,FAlert f -> {h with log = nfs; 
                                alert = Alert.addFragment ki h.alert r f}
    | Application_data,FAppData f -> {h with log = nfs; 
                                             appdata = AppDataStream.addFragment ki h.appdata r f}
