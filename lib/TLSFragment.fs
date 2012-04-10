module TLSFragment

open Error
open Bytes
open TLSInfo
open Formats
open CipherSuites
open DataStream
open StatefulPlain

type history = {
  handshake: Handshake.stream;
  alert: Alert.stream;
  ccs: Handshake.stream;
  appdata: AppDataStream.stream;
}

type fragment =
    | FHandshake of Handshake.fragment
    | FCCS of Handshake.ccsFragment
    | FAlert of Alert.fragment
    | FAppData of AppDataStream.fragment

let emptyHistory ki = {
  handshake = init ki // HandshakePlain.emptyStream ki;
  alert = init ki // AlertPlain.emptyStream ki;
  ccs = init ki // HandshakePlain.emptyStream ki;
  appdata = init ki // AppDataStream.emptyStream ki;
}

let addToStreams (ki:KeyInfo) ct ss r f =
    match (ct,f) with
    | Handshake,FHandshake(d) -> {ss with handshake = append ki ss.handshake r d}
    | Alert,FAlert(d) -> {ss with alert = append ki ss.alert r d}
    | Change_cipher_spec,FCCS(d) -> {ss with ccs = append ki ss.ccs r d}
    | Application_data,FAppData(d) -> {ss with appdata = append ki ss.appdata r d}
    | _,_ -> unexpectedError "[addToStreams] Incompatible content and fragment types"

let makeAD ki ct =
    let pv = ki.sinfo.protocol_version in
    let bct  = ctBytes ct in
    let bver = versionBytes pv in
    if pv = SSL_3p0 
    then bct
    else bct @| bver

let fragment ki (ct:ContentType) (h:history) (rg:DataStream.range) b = 
    match ct with
    | Handshake ->          FHandshake(delta ki h.handshake rg b)
    | Change_cipher_spec -> FCCS(delta ki h.ccs rg b)
    | Alert ->              FAlert(delta ki h.alert rg b)
    | Application_data ->   FAppData(delta ki h.appdata rg b)


let repr ki (ct:ContentType) (h:history) (rg:DataStream.range) frag =
    match frag with
    | FHandshake(f) -> deltaRepr ki h.handshake rg f
    | FCCS(f) -> deltaRepr ki h.ccs rg f
    | FAlert(f) -> deltaRepr ki h.alert rg f
    | FAppData(f) -> deltaRepr ki h.appdata rg f

let contents (ki:KeyInfo) (ct:ContentType) (h:history) (rg:range) f =
    match f with
        | FHandshake(f) -> DataStream.contents ki h.handshake rg f
        | FCCS(f) -> DataStream.contents ki h.ccs rg f
        | FAlert(f) -> DataStream.contents ki h.alert rg f
        | FAppData(f) -> DataStream.contents ki h.appdata rg f

let construct (ki:KeyInfo) (ct:ContentType) (h:history) (rg:range) sb =
    match ct with
        | Handshake -> FHandshake(DataStream.construct ki h.handshake rg sb)     
        | Change_cipher_spec -> FCCS(DataStream.construct ki h.ccs rg sb)
        | Alert -> FAlert(DataStream.construct ki h.alert rg sb)
        | Application_data -> FAppData(DataStream.construct ki h.appdata rg sb)  

let TLSFragmentToFragment ki ct ss h rg f =
    let sb = contents ki ct ss rg f in
    StatefulPlain.construct ki h (makeAD ki ct) rg sb

let fragmentToTLSFragment ki ct ss h rg f =
    let sb = StatefulPlain.contents ki h (makeAD ki ct) rg f in
    construct ki ct ss rg sb