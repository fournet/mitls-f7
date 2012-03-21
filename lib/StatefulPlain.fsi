module StatefulPlain
open Error
open Bytes
open TLSInfo
open DataStream
open Formats
open CipherSuites

type data = bytes

type fragment 

val addFragment: KeyInfo -> TLSFragment.history -> data -> range -> fragment -> TLSFragment.history

val fragment: KeyInfo -> TLSFragment.history -> bytes -> range -> bytes -> fragment
val repr: KeyInfo -> TLSFragment.history -> bytes -> range -> fragment -> bytes

val makeAD: int -> bytes -> bytes
val parseAD: bytes -> int * bytes

val TLSFragmentToFragment: KeyInfo -> ContentType -> TLSFragment.history -> DataStream.range -> TLSFragment.fragment -> fragment
val fragmentToTLSFragment: KeyInfo -> ContentType -> TLSFragment.history -> DataStream.range -> fragment -> TLSFragment.fragment
