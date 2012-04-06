module TLSFragment

open Bytes
open TLSInfo
open Formats
open CipherSuites
open DataStream

// Plain type for Dispatch
type history = {
  handshake: HandshakePlain.stream;
  alert: AlertPlain.stream;
  ccs: HandshakePlain.stream;
  appdata: AppDataStream.stream;
}

val emptyHistory: KeyInfo -> history

type fragment =
    | FHandshake of HandshakePlain.fragment
    | FCCS of HandshakePlain.ccsFragment
    | FAlert of AlertPlain.fragment
    | FAppData of AppDataStream.fragment

val addToStreams: KeyInfo -> ContentType -> history -> range -> fragment -> history

val TLSFragmentRepr: KeyInfo -> ContentType -> history -> range -> fragment -> bytes
val TLSFragment: KeyInfo -> ContentType -> history -> range -> bytes -> fragment

type addData = bytes
val makeAD: ProtocolVersion -> ContentType -> addData
//val parseAD: ProtocolVersion -> addData -> ContentType 

//val emptyHistory: KeyInfo -> history
//val addFragment: KeyInfo -> ContentType -> history -> range -> fragment -> history
