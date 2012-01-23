module TLSFragment

open Bytes
open TLSInfo
open Formats

type fragment =
    | FHandshake of Handshake.fragment
    | FCCS of Handshake.ccsFragment
    | FAlert of Alert.fragment
    | FAppData of AppDataPlain.fragment

let repr ki tlen (ct:ContentType) frag =
    match frag with
    | FHandshake(f) -> Handshake.repr ki tlen f
    | FCCS(f) -> Handshake.ccsRepr ki tlen f
    | FAlert(f) -> Alert.repr ki tlen f
    | FAppData(f) -> AppDataPlain.repr ki tlen f

let fragment ki tlen (ct:ContentType) b =
    match ct with
    | Handshake ->          FHandshake(Handshake.fragment ki tlen b)
    | Change_cipher_spec -> FCCS(Handshake.ccsFragment ki tlen b)
    | Alert ->              FAlert(Alert.fragment ki tlen b)
    | Application_data ->   FAppData(AppDataPlain.fragment ki tlen b)

type addData = bytes
type AEADFragment = {b:bytes}
let AEADFragment (ad:addData) b = {b=b}
let AEADRepr (ad:addData) f = f.b

let AEADToDispatch (ki:KeyInfo) (i:int) (ct:ContentType) (ad:addData) aead = fragment ki i ct aead.b
let DispatchToAEAD (ki:KeyInfo) (i:int) (ct:ContentType) (ad:addData) disp = {b = repr ki i ct disp}