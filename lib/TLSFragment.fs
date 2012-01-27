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

let TLSFragmentRepr ki tlen seqn (ct:ContentType) frag =
    match frag with
    | FHandshake(f) -> Handshake.repr ki tlen seqn f
    | FCCS(f) -> Handshake.ccsRepr ki tlen seqn f
    | FAlert(f) -> Alert.repr ki tlen seqn f
    | FAppData(f) -> AppDataPlain.repr ki tlen seqn f

let TLSFragment ki tlen seqn (ct:ContentType) b =
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

type AEADPlain = bytes
type AEADMsg = bytes
let AEADPlain (ki:KeyInfo) (tlen:int) (ad:addData) (b:bytes) = b
let AEADRepr (ki:KeyInfo) (tlen:int) (ad:addData) (f:bytes) = f

let AEADPlainToTLSFragment (ki:KeyInfo) (i:int) (ad:addData) (aead:AEADPlain) = 
  let (seq,ct) = parseAD ki.sinfo.protocol_version ad in
    TLSFragment ki i seq ct aead

let TLSFragmentToAEADPlain (ki:KeyInfo) (i:int) (seqn:int) (ct:ContentType) (disp:fragment) = 
  let ad = makeAD ki.sinfo.protocol_version seqn ct in
    TLSFragmentRepr ki i seqn ct disp

