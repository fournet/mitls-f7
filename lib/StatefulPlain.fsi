module StatefulPlain
open Error
open Bytes
open TLSInfo
open DataStream
open Formats
open CipherSuites

type data = bytes

type history
type fragment = sbytes

val emptyHistory: KeyInfo -> history
val addToHistory: KeyInfo -> history -> data -> range -> sbytes -> history

//val addFragment: KeyInfo -> TLSFragment.history -> data -> range -> fragment -> TLSFragment.history

val fragment: KeyInfo -> TLSFragment.history -> bytes -> range -> bytes -> fragment
val repr: KeyInfo -> TLSFragment.history -> bytes -> range -> fragment -> bytes

val TLSFragmentToFragment: KeyInfo -> ContentType -> history -> TLSFragment.history -> range -> TLSFragment.fragment -> fragment
val fragmentToTLSFragment: KeyInfo -> ContentType -> history -> TLSFragment.history -> range -> fragment -> TLSFragment.fragment

val makeAD: nat -> bytes -> bytes
// val parseAD: bytes -> nat * bytes