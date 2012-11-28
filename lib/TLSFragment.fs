module TLSFragment

open Error
open Bytes
open TLSInfo
open TLSConstants


type history = {
  handshake: HSFragment.stream // Handshake.stream;
  alert: HSFragment.stream // Alert.stream;
  ccs: HSFragment.stream // Handshake.stream;
  appdata: DataStream.stream // AppData.stream;
}

type fragment =
    | FHandshake of HSFragment.fragment // Handshake.fragment
    | FCCS of HSFragment.fragment // Handshake.ccsFragment
    | FAlert of HSFragment.fragment // Alert.fragment
    | FAppData of AppFragment.fragment // AppData.fragment
type plain = fragment

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

let plain ki (ct:ContentType) (h:history) (rg:range) b = 
    match ct with
    | Handshake ->          FHandshake(HSFragment.fragmentPlain ki rg b)
    | Change_cipher_spec -> FCCS(HSFragment.fragmentPlain ki rg b)
    | Alert ->              FAlert(HSFragment.fragmentPlain ki rg b)
    | Application_data ->   FAppData(AppFragment.fragmentPlain ki rg b)


let repr ki (ct:ContentType) (h:history) (rg:range) frag =
    match frag with
    | FHandshake(f) -> HSFragment.fragmentRepr ki rg f
    | FCCS(f) -> HSFragment.fragmentRepr ki rg f
    | FAlert(f) -> HSFragment.fragmentRepr ki rg f
    | FAppData(f) -> AppFragment.fragmentRepr ki rg f

let HSPlainToRecordPlain    (e:epoch) (h:history) (r:range) (f:HSFragment.fragment) = FHandshake(f)
let RecordPlainToHSPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FHandshake(f) -> f
    | _ -> unexpectedError "[RecordPlainToHSPlain] invoked on an invalid fragment"
let CCSPlainToRecordPlain   (e:epoch) (h:history) (r:range) (f:HSFragment.fragment) = FCCS(f)
let RecordPlainToCCSPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FCCS(f) -> f
    | _ -> unexpectedError "[RecordPlainToCCSPlain] invoked on an invalid fragment"
let AlertPlainToRecordPlain (e:epoch) (h:history) (r:range) (f:HSFragment.fragment) = FAlert(f)
let RecordPlainToAlertPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FAlert(f) -> f
    | _ -> unexpectedError "[RecordPlainToAlertPlain] invoked on an invalid fragment"
let AppPlainToRecordPlain   (e:epoch) (h:history) (r:range) (f:AppFragment.fragment) = FAppData(f)
let RecordPlainToAppPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FAppData(f) -> f
    | _ -> unexpectedError "[RecordPlainToAppPlain] invoked on an invalid fragment"

let addToHistory (e:epoch) ct ss r frag =
  match ct,frag with
    | Handshake,FHandshake(_) ->
        let f = RecordPlainToHSPlain e ss r frag in
        let s' = HSFragment.extend e ss.handshake r f in
        {ss with handshake = s'} 
    | Alert,FAlert(_) ->
        let f = RecordPlainToAlertPlain e ss r frag in
        let s' = HSFragment.extend e ss.alert r f in
          {ss with alert = s'} 
    | Change_cipher_spec,FCCS(_) ->
        let f = RecordPlainToCCSPlain e ss r frag in
        let s' = HSFragment.extend e ss.ccs r f in
          {ss  with ccs = s'} 
    | Application_data,FAppData(_) ->
        let f = RecordPlainToAppPlain e ss r frag in
        let d,s' = AppFragment.delta e ss.appdata r f in
          {ss with appdata = s'}
    | _,_ -> unexpectedError "[addToHistory] invoked on an invalid contenttype/fragment"
