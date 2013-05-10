module TLSFragment

open Error
open TLSError
open Bytes
open TLSInfo
open TLSConstants
open Range

type fragment =
    | FHandshake of HSFragment.fragment //Cf Handshake.fragment
    | FCCS of HSFragment.fragment //CF Handshake.ccsFragment
    | FAlert of HSFragment.fragment //CF Alert.fragment
    | FAppData of AppFragment.fragment //CF AppData.fragment
type plain = fragment

type history = {
  handshake: HSFragment.stream //CF Handshake.stream;
  ccs:       HSFragment.stream //CF Handshake.stream;
  alert:     HSFragment.stream //CF Alert.stream;
  appdata:   DataStream.stream //CF AppData.stream;
}

let emptyHistory ki =
    let es = HSFragment.init ki in
    let ehApp = DataStream.init ki in
    { handshake = es;
      ccs = es;
      alert = es;
      appdata = ehApp} in

let handshakeHistory (e:id) h = h.handshake
let ccsHistory (e:id) h = h.ccs
let alertHistory (e:id) h = h.alert

let fragment ki ct rg b =  
    match ct with
    | Handshake          -> FHandshake(HSFragment.fragmentPlain ki rg b)
    | Change_cipher_spec -> FCCS(HSFragment.fragmentPlain ki rg b)
    | Alert              -> FAlert(HSFragment.fragmentPlain ki rg b)
    | Application_data   -> FAppData(AppFragment.plain ki rg b)

let plain ki (ct:ContentType) (h:history) (rg:range) b = 
      let i = id ki in
        fragment i ct rg b 

let reprFragment ki (ct:ContentType) (rg:range) frag =
    match frag with
    | FHandshake(f) -> HSFragment.fragmentRepr ki rg f
    | FCCS(f)       -> HSFragment.fragmentRepr ki rg f
    | FAlert(f)     -> HSFragment.fragmentRepr ki rg f
    | FAppData(f)   -> AppFragment.repr ki rg f

let repr ki ct (h:history) rg frag = 
  let i = id ki in
  reprFragment i ct rg frag

let HSPlainToRecordPlain    (e:epoch) (h:history) (r:range) (f:HSFragment.plain) = FHandshake(f)
let CCSPlainToRecordPlain   (e:epoch) (h:history) (r:range) (f:HSFragment.plain) = FCCS(f)
let AlertPlainToRecordPlain (e:epoch) (h:history) (r:range) (f:HSFragment.plain) = FAlert(f)
let AppPlainToRecordPlain   (e:epoch) (h:history) (r:range) (f:AppFragment.plain)= FAppData(f)

let RecordPlainToHSPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FHandshake(f) -> f
    | FCCS(_) 
    | FAlert(_) 
    | FAppData(_)   -> unreachable "[RecordPlainToHSPlain] invoked on an invalid fragment"
let RecordPlainToCCSPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FCCS(f)       -> f
    | FHandshake(_) 
    | FAlert(_) 
    | FAppData(_)   -> unreachable "[RecordPlainToCCSPlain] invoked on an invalid fragment"
let RecordPlainToAlertPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FAlert(f)     -> f
    | FHandshake(_) 
    | FCCS(_) 
    | FAppData(_)   -> unreachable "[RecordPlainToAlertPlain] invoked on an invalid fragment"
let RecordPlainToAppPlain    (e:epoch) (h:history) (r:range) ff =
    match ff with
    | FAppData(f)   -> f
    | FHandshake(_) 
    | FCCS(_) 
    | FAlert(_)     -> unreachable "[RecordPlainToAppPlain] invoked on an invalid fragment"

let extendHistory (e:epoch) ct ss r frag =
  let i = id e in
  match ct,frag with
    | Handshake,FHandshake(f)      -> let s' = HSFragment.extend i ss.handshake r f in 
                                      {ss with handshake = s'} 
    | Alert,FAlert(f)              -> let s' = HSFragment.extend i ss.alert r f in 
                                      {ss with alert = s'} 
    | Change_cipher_spec,FCCS(f)   -> let s' = HSFragment.extend i ss.ccs r f in 
                                      {ss  with ccs = s'} 
    | Application_data,FAppData(f) -> let d,s' = AppFragment.delta e ss.appdata r f in 
                                      {ss with appdata = s'}
    | _,_                          -> unexpected "[extendHistory] invoked on an invalid contenttype/fragment"
    //CF unreachable too, but we'd need to list the other 12 cases to prove it. 

#if ideal
let widen e ct r0 f0 =
    let i = id e in
    let r1 = rangeClass i r0 in
    match ct,f0 with
    | Handshake,FHandshake(f)      -> let f1 = HSFragment.widen i r0 r1 f in 
                                      FHandshake(f1)
    | Alert,FAlert(f)              -> let f1 = HSFragment.widen i r0 r1 f in 
                                      FAlert(f1)
    | Change_cipher_spec,FCCS(f)   -> let f1 = HSFragment.widen i r0 r1 f in
                                      FCCS(f1)
    | Application_data,FAppData(f) -> let f1 = AppFragment.widen e r0 f in 
                                      FAppData(f1)
    | _,_                          -> unexpected "[widen] invoked on an invalid contenttype/fragment"
    //CF unreachable too
#endif
