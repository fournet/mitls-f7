module TLSFragment

open Error
open Bytes
open TLSInfo
open Formats
open CipherSuites
open DataStream

type history = {
  handshake: HandshakePlain.stream;
  alert: AlertPlain.stream;
  ccs: HandshakePlain.stream;
  appdata: AppDataStream.stream;
}

type fragment =
    | FHandshake of HandshakePlain.fragment
    | FCCS of HandshakePlain.ccsFragment
    | FAlert of AlertPlain.fragment
    | FAppData of AppDataStream.fragment

let emptyHistory ki = {
  handshake = init ki; // HandshakePlain.emptyStream ki;
  alert = init ki; // AlertPlain.emptyStream ki;
  ccs = init ki; // HandshakePlain.emptyStream ki;
  appdata = init ki; // AppDataStream.emptyStream ki;
}

let addToStreams (ki:KeyInfo) ct ss r f =
    match (ct,f) with
    | Handshake,FHandshake(d) -> {ss with handshake = append ki ss.handshake r d}
    | Alert,FAlert(d) -> {ss with alert = append ki ss.alert r d}
    | Change_cipher_spec,FCCS(d) -> {ss with ccs = append ki ss.ccs r d}
    | Application_data,FAppData(d) -> {ss with appdata = append ki ss.appdata r d}
    | _,_ -> unexpectedError "[addToStreams] Incompatible content and fragment types"

type addData = bytes

let makeAD pv ct =
    let bct  = ctBytes ct in
    let bver = versionBytes pv in
    if pv = SSL_3p0 
    then bct
    else bct @| bver

//let parseAD pv ad =
//    if pv = SSL_3p0 then
//      match parseCT ad with
//        | Error(x,y) -> unexpectedError "[parseAD] should always be invoked on valid additional data"
//        | Correct(ct) -> ct
//    else
//      let (ct1,bver) = Bytes.split ad 1 in
//        if bver <> versionBytes pv then
//          unexpectedError "[parseAD] should always be invoked on valid additional data"
//        else
//          match parseCT ct1 with
//            | Error(x,y) -> unexpectedError "[parseAD] should always be invoked on valid additional data"
//            | Correct(ct) -> ct


let TLSFragmentRepr ki (ct:ContentType) (h:history) (rg:DataStream.range) frag =
    match frag with
    | FHandshake(f) -> HandshakePlain.repr ki h.handshake rg f
    | FCCS(f) -> HandshakePlain.ccsRepr ki h.ccs rg f
    | FAlert(f) -> AlertPlain.repr ki h.alert rg f
    | FAppData(f) -> AppDataStream.repr ki h.appdata rg f

let TLSFragment ki (ct:ContentType) (h:history) (rg:DataStream.range) b = 
    match ct with
    | Handshake ->          FHandshake(HandshakePlain.fragment ki h.handshake rg b)
    | Change_cipher_spec -> FCCS(HandshakePlain.ccsFragment ki h.ccs rg b)
    | Alert ->              FAlert(AlertPlain.fragment ki h.alert rg b)
    | Application_data ->   FAppData(AppDataStream.fragment ki h.appdata rg b)

let addFragment ki ct h r f = 
  //let nfs = (ct,h,r,f)::h.log in
  match ct,f with
    | Handshake,FHandshake f -> {h with //log = nfs; 
                                        handshake = append (* HandshakePlain.addFragment *) ki h.handshake r f}
    | Change_cipher_spec,FCCS f -> {h with // log = nfs; 
                                           ccs = append (* HandshakePlain.addCCSFragment *) ki h.ccs r f}
    | Alert,FAlert f -> {h with // log = nfs; 
                                alert = append (* AlertPlain.addFragment *) ki h.alert r f}
    | Application_data,FAppData f -> {h with // log = nfs; 
                                             appdata = append (* AppDataStream.addFragment *) ki h.appdata r f}
    | _,_ -> unexpectedError "[addFragment] Inconsistent fragment and content types"
