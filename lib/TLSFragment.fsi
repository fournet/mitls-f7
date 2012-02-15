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
val TLSFragmentRepr: KeyInfo -> range -> int -> ContentType -> fragment -> bytes
val TLSFragment: KeyInfo -> range -> int -> ContentType -> bytes -> fragment

type addData = bytes
val makeAD: ProtocolVersion -> ContentType -> addData
val parseAD: ProtocolVersion -> addData -> ContentType 

