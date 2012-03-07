module StatefulPlain
open Error
open Bytes
open TLSKey
open TLSInfo
open DataStream
open Formats
open CipherSuites

type data = bytes
type prestate // = {
//  key: AEADKey;
//  iv: ENCKey.iv3;
//  seqn: int;
//  history: TLSFragment.history;
//}

type state = prestate
type reader = state
type writer = state

type fragment 

val initState: KeyInfo -> AEADKey -> ENCKey.iv3 -> state
val getKey: KeyInfo -> state -> AEADKey
val getIV: KeyInfo -> state -> ENCKey.iv3
val updateIV: KeyInfo -> state -> ENCKey.iv3 -> state
val addFragment: KeyInfo -> state -> data -> range -> fragment -> state
val sequenceNo: KeyInfo -> state -> int

val fragment: KeyInfo -> state -> bytes -> range -> bytes -> fragment
val repr: KeyInfo -> state -> bytes -> range -> fragment -> bytes

val makeAD: int -> bytes -> bytes
val parseAD: bytes -> int * bytes

val TLSFragmentToFragment: KeyInfo -> range -> int -> ContentType -> TLSFragment.fragment -> fragment
val fragmentToTLSFragment: KeyInfo -> state -> bytes -> range -> fragment -> TLSFragment.fragment

val emptyState: KeyInfo -> state
