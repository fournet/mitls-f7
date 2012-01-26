module TLSFragment

open Error
open Bytes
open TLSInfo
open Formats
open CipherSuites

type fragment =
    | FHandshake of Handshake.fragment
    | FCCS of Handshake.ccsFragment
    | FAlert of Alert.fragment
    | FAppData of AppDataPlain.fragment

let repr ki tlen seqn (ct:ContentType) frag =
    match frag with
    | FHandshake(f) -> Handshake.repr ki tlen seqn f
    | FCCS(f) -> Handshake.ccsRepr ki tlen seqn f
    | FAlert(f) -> Alert.repr ki tlen seqn f
    | FAppData(f) -> AppDataPlain.repr ki tlen seqn f

let TLSfragment ki tlen seqn (ct:ContentType) b =
    match ct with
    | Handshake ->          FHandshake(Handshake.fragment ki tlen seqn b)
    | Change_cipher_spec -> FCCS(Handshake.ccsFragment ki tlen seqn b)
    | Alert ->              FAlert(Alert.fragment ki tlen seqn b)
    | Application_data ->   FAppData(AppDataPlain.fragment ki tlen seqn b)

type addData = bytes

let makeAD pv seqn ct =
    let bseq = bytes_of_seq seqn in
    let bct  = ctBytes ct in
    let bver = versionBytes pv in
    if pv = SSL_3p0 
    then bseq @| bct
    else bseq @| bct @| bver

let parseAD pv ad =
    if pv = SSL_3p0 then
        let (seq8,ct1) = split ad 8 in
        let seqn = seq_of_bytes seq8 in
        match parseCT ct1 with
        | Error(x,y) -> unexpectedError "[parseAD] should always be invoked on valid additional data"
        | Correct(ct) -> (seqn,ct)
    else
        let (seq8,rem) = split ad 8 in
        let (ct1,_) = split rem 1 in
        let seqn = seq_of_bytes seq8 in
        match parseCT ct1 with
        | Error(x,y) -> unexpectedError "[parseAD] should always be invoked on valid additional data"
        | Correct(ct) -> (seqn,ct)

type AEADFragment = fragment
let AEADFragment (ki:KeyInfo) (tlen:int) (ad:addData) b =
    let (seqn,ct) = parseAD ki.sinfo.protocol_version ad in
    TLSfragment ki tlen seqn ct b

let AEADRepr (ki:KeyInfo) (tlen:int) (ad:addData) f =
    let (seqn,ct) = parseAD ki.sinfo.protocol_version ad in
    repr ki tlen seqn ct f

let AEADToDispatch (ki:KeyInfo) (i:int) (seqn:int) (ct:ContentType) (ad:addData) (aead:AEADFragment) = aead
let DispatchToAEAD (ki:KeyInfo) (i:int) (seqn:int) (ct:ContentType) (ad:addData) (disp:fragment) = disp