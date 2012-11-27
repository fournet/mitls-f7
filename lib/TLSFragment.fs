module TLSFragment

open Error
open Bytes
open TLSInfo
open TLSConstants


type prehistory = {
  handshake: HSFragment.stream // Handshake.stream;
  alert: HSFragment.stream // Alert.stream;
  ccs: HSFragment.stream // Handshake.stream;
  appdata: DataStream.stream // AppData.stream;
}

type history = prehistory

type fragment =
    | FHandshake of HSFragment.fragment // Handshake.fragment
    | FCCS of HSFragment.fragment // Handshake.ccsFragment
    | FAlert of HSFragment.fragment // Alert.fragment
    | FAppData of AppFragment.fragment // AppData.fragment

let emptyHistory ki =
    let es = HSFragment.init ki in
    let ehApp = DataStream.init ki in
      { handshake = es;
        alert = es;
        ccs = es;
        appdata = ehApp} in

// let historyStream (ki:epoch) ct ss =
//     match ct with
//     | Handshake -> ss.handshake
//     | Alert -> ss.alert
//     | Change_cipher_spec -> ss.ccs
//     | Application_data -> ss.appdata

let fragmentPlain ki (ct:ContentType) (h:history) (rg:range) b = 
    match ct with
    | Handshake ->          FHandshake(HSFragment.fragmentPlain ki rg b)
    | Change_cipher_spec -> FCCS(HSFragment.fragmentPlain ki rg b)
    | Alert ->              FAlert(HSFragment.fragmentPlain ki rg b)
    | Application_data ->   FAppData(AppFragment.fragmentPlain ki rg b)


let fragmentRepr ki (ct:ContentType) (h:history) (rg:range) frag =
    match frag with
    | FHandshake(f) -> HSFragment.fragmentRepr ki rg f
    | FCCS(f) -> HSFragment.fragmentRepr ki rg f
    | FAlert(f) -> HSFragment.fragmentRepr ki rg f
    | FAppData(f) -> AppFragment.fragmentRepr ki rg f


// let contents (ki:epoch) (ct:ContentType) (h:history) (rg:range) f =
//     match f with
//         | FHandshake(f) -> f
//         | FCCS(f) -> f
//         | FAlert(f) -> f
//         | FAppData(f) -> f
//             
// 
// let construct (ki:epoch) (ct:ContentType) (h:history) (rg:range) sb =
//     match ct with
//         | Handshake -> FHandshake(sb)
//         | Change_cipher_spec -> FCCS(sb)
//         | Alert -> FAlert(sb)
//         | Application_data -> FAppData(sb)

let addToHistory (ki:epoch) ct ss r frag =
  match ct,frag with
    | (Handshake, FHandshake(f)) -> 
        let s' = HSFragment.extend ki ss.handshake r f in
        {ss with handshake = s'} 
    | (Alert, FAlert(f)) -> 
        let s' = HSFragment.extend ki ss.alert r f in
          {ss with alert = s'} 
    | (Change_cipher_spec, FCCS(f)) -> 
        let s' = HSFragment.extend ki ss.ccs r f in
          {ss  with ccs = s'} 
    | (Application_data, FAppData(f)) -> 
        let d,s' = AppFragment.delta ki ss.appdata r f in
          {ss with appdata = s'}
    | (_,_) -> unexpectedError "[addToHistory] invoked on inconstitent content type/fragment"

