module TLSFragment

open Error
open Bytes
open TLSInfo
open Formats
open CipherSuites
open DataStream
open StatefulPlain

type history = {
  handshake: stream // Handshake.stream;
  alert: stream // Alert.stream;
  ccs: stream // Handshake.stream;
  appdata: stream // AppDataStream.stream;
}

type fragment =
    | FHandshake of Fragment.fragment // Handshake.fragment
    | FCCS of Fragment.fragment // Handshake.ccsFragment
    | FAlert of Fragment.fragment // Alert.fragment
    | FAppData of Fragment.fragment // AppDataStream.fragment

let emptyHistory ki = {
  handshake = init ki // HandshakePlain.emptyStream ki;
  alert = init ki // AlertPlain.emptyStream ki;
  ccs = init ki // HandshakePlain.emptyStream ki;
  appdata = init ki // AppDataStream.emptyStream ki;
}

let addToStreams (ki:KeyInfo) ct ss r f =
    match (ct,f) with
    | Handshake,FHandshake(ff) -> 
        let d,s' = Fragment.delta ki ss.handshake r ff in
          {ss with handshake = s'}
    | Alert,FAlert(ff) -> 
        let d,s' = Fragment.delta ki ss.alert r ff in
          {ss with alert = s'}
    | Change_cipher_spec,FCCS(ff) -> 
        let d,s' = Fragment.delta ki ss.ccs r ff in
          {ss with ccs = s'}
    | Application_data,FAppData(ff) -> 
        let d,s' = Fragment.delta ki ss.appdata r ff in
          {ss with appdata = s'}
    | _,_ -> unexpectedError "[addToStreams] Incompatible content and fragment types"

let makeAD ki ct =
    let pv = ki.sinfo.protocol_version in
    let bct  = ctBytes ct in
    let bver = versionBytes pv in
    if pv = SSL_3p0 
    then bct
    else bct @| bver

let fragmentPlain ki (ct:ContentType) (h:history) (rg:DataStream.range) b = 
    match ct with
    | Handshake ->          FHandshake(Fragment.fragmentPlain ki rg b)
    | Change_cipher_spec -> FCCS(Fragment.fragmentPlain ki rg b)
    | Alert ->              FAlert(Fragment.fragmentPlain ki rg b)
    | Application_data ->   FAppData(Fragment.fragmentPlain ki rg b)


let fragmentRepr ki (ct:ContentType) (h:history) (rg:DataStream.range) frag =
    match frag with
    | FHandshake(f) -> Fragment.fragmentRepr ki rg f
    | FCCS(f) -> Fragment.fragmentRepr ki rg f
    | FAlert(f) -> Fragment.fragmentRepr ki rg f
    | FAppData(f) -> Fragment.fragmentRepr ki rg f

let contents (ki:KeyInfo) (ct:ContentType) (h:history) (rg:range) f =
    match f with
        | FHandshake(f) -> f
        | FCCS(f) -> f
        | FAlert(f) -> f
        | FAppData(f) -> f
            

let construct (ki:KeyInfo) (ct:ContentType) (h:history) (rg:range) sb =
    match ct with
        | Handshake -> FHandshake(sb)
        | Change_cipher_spec -> FCCS(sb)
        | Alert -> FAlert(sb)
        | Application_data -> FAppData(sb)

let TLSFragmentToFragment ki ct ss h rg f =
    let sb = contents ki ct ss rg f in
    StatefulPlain.construct ki h (makeAD ki ct) rg sb

let fragmentToTLSFragment ki ct ss h rg f =
    let sb = StatefulPlain.contents ki h (makeAD ki ct) rg f in
    construct ki ct ss rg sb
