module TLSFragment

open Bytes
open TLSInfo
open Formats
open CipherSuites

// Plain type for Dispatch
type fragment =
    | FHandshake of Handshake.fragment
    | FCCS of Handshake.ccsFragment
    | FAlert of Alert.fragment
    | FAppData of AppDataStream.fragment
val TLSFragmentRepr: KeyInfo -> int -> int -> ContentType -> fragment -> bytes
val TLSFragment: KeyInfo -> int -> int -> ContentType -> bytes -> fragment

// Plain type for AEAD
type addData = bytes
val makeAD: ProtocolVersion -> int -> ContentType -> bytes

type AEADPlain = bytes
type AEADMsg = bytes
val AEADPlain: KeyInfo -> int -> addData -> bytes -> AEADPlain
val AEADRepr: KeyInfo -> int -> addData -> AEADPlain -> bytes

val AEADPlainToTLSFragment: KeyInfo -> int -> addData -> AEADPlain -> fragment
val TLSFragmentToAEADPlain: KeyInfo -> int -> int -> ContentType -> fragment -> AEADPlain
