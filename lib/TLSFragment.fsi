module TLSFragment

open Bytes
open TLSInfo
open Formats
open CipherSuites
open DataStream

// Plain type for Dispatch
type fragment =
    | FHandshake of Handshake.fragment
    | FCCS of Handshake.ccsFragment
    | FAlert of Alert.fragment
    | FAppData of AppDataStream.fragment
and history = {
  handshake: Handshake.stream;
  alert: Alert.stream;
  ccs: Handshake.stream;
  appdata: AppDataStream.stream;
  log: fragmentSequence;
}
and fragmentSequence = (ContentType * history * range * fragment) list


val TLSFragmentRepr: KeyInfo -> ContentType -> history -> range -> fragment -> bytes
val TLSFragment: KeyInfo -> ContentType -> history -> range -> bytes -> fragment

type addData = bytes
val makeAD: ProtocolVersion -> ContentType -> addData
val parseAD: ProtocolVersion -> addData -> ContentType 

val emptyHistory: KeyInfo -> history
val addFragment: KeyInfo -> ContentType -> history -> range -> fragment -> history
