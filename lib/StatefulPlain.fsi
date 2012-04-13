module StatefulPlain
open Bytes
open Formats
open TLSInfo
open DataStream
open AEADPlain

type data = bytes

type prehistory
type history  = (nat * prehistory)
type fragment

val emptyHistory: KeyInfo -> history
val addToHistory: KeyInfo -> history -> data -> range -> fragment -> history

val makeAD: KeyInfo -> history -> data -> AEADPlain.data

val fragment: KeyInfo -> history -> data -> range -> bytes -> fragment
val repr:     KeyInfo -> history -> data -> range -> fragment -> bytes

val contents:  KeyInfo -> history -> data -> range -> fragment -> sbytes
val construct: KeyInfo -> history -> data -> range -> sbytes -> fragment

val FragmentToAEADPlain: KeyInfo -> history -> data -> range -> fragment -> AEADPlain
val AEADPlainToFragment: KeyInfo -> history -> data -> range -> AEADPlain -> fragment

//val TLSFragmentToFragment: KeyInfo -> ContentType -> history -> TLSFragment.history -> range -> TLSFragment.fragment -> fragment
//val fragmentToTLSFragment: KeyInfo -> ContentType -> history -> TLSFragment.history -> range -> fragment -> TLSFragment.fragment