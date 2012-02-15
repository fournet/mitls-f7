module StatefulPlain
open Error
open Bytes
open TLSInfo
open DataStream
open Formats
open CipherSuites

type addData = bytes
type state 
type fragment = TLSFragment.fragment

val emptyState: KeyInfo -> state
val stateLength:KeyInfo -> state -> int

val addFragment: KeyInfo -> state -> bytes -> range -> 
                 fragment -> state

val TLSFragmentToFragment: KeyInfo -> range -> int -> ContentType -> TLSFragment.fragment -> fragment
val fragmentToTLSFragment: KeyInfo -> state -> bytes -> range -> fragment -> TLSFragment.fragment

val fragment: KeyInfo -> state -> bytes -> range -> bytes -> fragment
val repr: KeyInfo -> state -> bytes -> range -> fragment -> bytes

val makeAD: int -> bytes -> bytes
val parseAD: bytes -> int * bytes
