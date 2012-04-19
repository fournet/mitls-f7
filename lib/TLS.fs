module TLS

open Bytes
open Error
open TLSInfo
open Tcp

let connect ns po = Dispatch.init ns Client po
let resume ns sid po = Dispatch.resume ns sid po

let rehandshake c po = Dispatch.rehandshake c po
let rekey c po = Dispatch.rekey c po

let accept list po =
    let ns = Tcp.accept list in
    Dispatch.init ns Server po
let accept_connected ns po = Dispatch.init ns Server po

let request c po = Dispatch.request c po

let read c = Dispatch.read c
let write c msg = Dispatch.write c msg
let shutdown c = Dispatch.shutdown c

let authorize c q = Dispatch.authorize c q
let refuse c q = Dispatch.refuse c q

let getInKI c = Dispatch.getInKI c
let getOutKI c = Dispatch.getOutKI c
let getSessionInfo ki = epochSI(ki)
let getInStream  c = Dispatch.getInStream c
let getOutStream c = Dispatch.getOutStream c