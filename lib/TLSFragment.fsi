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

// Plain type for AEAD
type addData = bytes
val makeAD: ProtocolVersion -> int -> ContentType -> bytes

type AEADPlain = fragment
type AEADMsg = fragment
val AEADPlain: KeyInfo -> range -> addData -> bytes -> AEADPlain
val AEADRepr: KeyInfo -> range -> addData -> AEADPlain -> bytes

val AEADPlainToTLSFragment: KeyInfo -> range -> addData -> AEADPlain -> fragment
val TLSFragmentToAEADPlain: KeyInfo -> range -> int -> ContentType -> fragment -> AEADPlain
