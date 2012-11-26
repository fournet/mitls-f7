module TLSFragment

open Error
open Bytes
open TLSInfo
open TLSConstants

open DataStream

type prehistory = {
  handshake: stream // Handshake.stream;
  alert: stream // Alert.stream;
  ccs: stream // Handshake.stream;
  appdata: stream // AppData.stream;
}

type history = prehistory

type fragment =
    | FHandshake of Fragment.fragment // Handshake.fragment
    | FCCS of Fragment.fragment // Handshake.ccsFragment
    | FAlert of Fragment.fragment // Alert.fragment
    | FAppData of Fragment.fragment // AppData.fragment

let emptyHistory ki =
    let eh = init ki in
      { handshake = eh;
        alert = eh;
        ccs = eh;
        appdata = eh} in

let historyStream (ki:epoch) ct ss =
    match ct with
    | Handshake -> ss.handshake
    | Alert -> ss.alert
    | Change_cipher_spec -> ss.ccs
    | Application_data -> ss.appdata

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


let contents (ki:epoch) (ct:ContentType) (h:history) (rg:range) f =
    match f with
        | FHandshake(f) -> f
        | FCCS(f) -> f
        | FAlert(f) -> f
        | FAppData(f) -> f
            

let construct (ki:epoch) (ct:ContentType) (h:history) (rg:range) sb =
    match ct with
        | Handshake -> FHandshake(sb)
        | Change_cipher_spec -> FCCS(sb)
        | Alert -> FAlert(sb)
        | Application_data -> FAppData(sb)

let addToHistory (ki:epoch) ct ss r frag =
  let ff = contents ki ct ss r frag in
  match ct with
    | Handshake -> 
        let d,s' = Fragment.delta ki ss.handshake r ff in
          {ss with handshake = s'} 
    | Alert -> 
        let d,s' = Fragment.delta ki ss.alert r ff in
          {ss with alert = s'} 
    | Change_cipher_spec -> 
        let d,s' = Fragment.delta ki ss.ccs r ff in
          {ss  with ccs = s'} 
    | Application_data -> 
        let d,s' = Fragment.delta ki ss.appdata r ff in
          {ss with appdata = s'} 

