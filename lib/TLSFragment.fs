module TLSFragment

open Bytes
open TLSInfo
open Formats

type fragment =
    | FHandshake of Handshake.fragment
    | FCCS of Handshake.ccsFragment
    | FAlert of Alert.fragment
    | FAppData of AppDataPlain.fragment

let repr ki tlen frag =
    match frag with
    | FHandshake(f) -> Handshake.repr ki tlen f
    | FCCS(f) -> Handshake.ccsRepr ki tlen f
    | FAlert(f) -> Alert.repr ki tlen f
    | FAppData(f) -> AppDataPlain.repr ki tlen f

let fragment ki b ct =
    match ct with
    | Handshake -> let ((tlen,f),b) = Handshake.fragment ki b in ((tlen,FHandshake(f)),b)
    | Change_cipher_spec -> let ((tlen,f),b) = Handshake.ccsFragment ki b in ((tlen,FCCS(f)),b)
    | Alert -> let ((tlen,f),b) = Alert.fragment ki b in ((tlen,FAlert(f)),b)
    | Application_data -> let ((tlen,f),b) = AppDataPlain.fragment ki b in ((tlen,FAppData(f)),b)
