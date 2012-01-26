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
    | FAppData of AppDataPlain.fragment
val repr: KeyInfo -> int -> int -> ContentType -> fragment -> bytes
val TLSfragment: KeyInfo -> int -> int -> ContentType -> bytes -> fragment

// Plain type for AEAD
type addData = bytes
val makeAD: ProtocolVersion -> int -> ContentType -> bytes

type AEADFragment = fragment
val AEADFragment: KeyInfo -> int -> addData -> bytes -> AEADFragment
val AEADRepr: KeyInfo -> int -> addData -> AEADFragment -> bytes

val AEADToDispatch: KeyInfo -> int -> int -> ContentType -> addData -> AEADFragment -> fragment
val DispatchToAEAD: KeyInfo -> int -> int -> ContentType -> addData -> fragment -> AEADFragment